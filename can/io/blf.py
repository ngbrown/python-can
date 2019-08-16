# coding: utf-8

"""
Implements support for BLF (Binary Logging Format) which is a proprietary
CAN log format from Vector Informatik GmbH (Germany).

No official specification of the binary logging format is available.
This implementation is based on Toby Lorenz' C++ library "Vector BLF" which is
licensed under GPLv3. https://bitbucket.org/tobylorenz/vector_blf.

The file starts with a header. The rest is one or more "log containers"
which consists of a header and some zlib compressed data, usually up to 128 kB
of uncompressed data each. This data contains the actual CAN messages and other
objects types.
"""

import struct
import zlib
import datetime
import time
import logging
from typing import List

from can.message import Message
from can.listener import Listener
from can.util import len2dlc, dlc2len, channel2int
from .generic import BaseIOHandler


class BLFParseError(Exception):
    """BLF file could not be parsed correctly."""


LOG = logging.getLogger(__name__)

# 0 = unknown, 2 = CANoe
APPLICATION_ID = 5

# signature ("LOGG"), header size,
# application ID, application major, application minor, application build,
# bin log major, bin log minor, bin log build, bin log patch,
# file size, uncompressed size, count of objects, count of objects read,
# time start (SYSTEMTIME), time stop (SYSTEMTIME)
FILE_HEADER_STRUCT = struct.Struct("<4sLBBBBBBBBQQLL8H8H")

# Pad file header to this size
FILE_HEADER_SIZE = 144

# signature ("LOBJ"), header size, header version, object size, object type
OBJ_HEADER_BASE_STRUCT = struct.Struct("<4sHHLL")

# flags, client index, object version, timestamp
OBJ_HEADER_V1_STRUCT = struct.Struct("<LHHQ")

# flags, timestamp status, object version, timestamp, original timestamp
OBJ_HEADER_V2_STRUCT = struct.Struct("<LBxHQQ")

# compression method, size uncompressed
LOG_CONTAINER_STRUCT = struct.Struct("<H6xL4x")

# channel, flags, dlc, arbitration id, data
CAN_MSG_STRUCT = struct.Struct("<HBBL8s")

# channel, flags, dlc, arbitration id, frame length, bit count, FD flags,
# valid data bytes, data
CAN_FD_MSG_STRUCT = struct.Struct("<HBBLLBBB5x64s")

# channel, dlc, valid payload length of data, tx count, arbitration id,
# frame length, flags, bit rate used in arbitration phase,
# bit rate used in data phase, time offset of brs field,
# time offset of crc delimiter field, bit count, direction,
# offset if extDataOffset is used, crc
CAN_FD_MSG_64_STRUCT = struct.Struct("<BBBBLLLLLLLHBBL")

# channel, length, flags, ecc, position, dlc, frame length, id, flags ext, data
CAN_ERROR_EXT_STRUCT = struct.Struct("<HHLBBBxLLH2x8s")

# commented event type, foreground color, background color, relocatable,
# group name length, marker name length, description length
GLOBAL_MARKER_STRUCT = struct.Struct("<LLL3xBLLL12x")


CAN_MESSAGE = 1
LOG_CONTAINER = 10
CAN_ERROR_EXT = 73
CAN_MESSAGE2 = 86
GLOBAL_MARKER = 96
CAN_FD_MESSAGE = 100
CAN_FD_MESSAGE_64 = 101

NO_COMPRESSION = 0
ZLIB_DEFLATE = 2

CAN_MSG_EXT = 0x80000000
REMOTE_FLAG = 0x80
EDL = 0x1
BRS = 0x2
ESI = 0x4

# CAN FD 64 Flags
REMOTE_FLAG_64 = 0x0010
EDL_64 = 0x1000
BRS_64 = 0x2000
ESI_64 = 0x4000

TIME_TEN_MICS = 0x00000001
TIME_ONE_NANS = 0x00000002


def timestamp_to_systemtime(timestamp):
    if timestamp is None or timestamp < 631152000:
        # Probably not a Unix timestamp
        return (0, 0, 0, 0, 0, 0, 0, 0)
    t = datetime.datetime.fromtimestamp(timestamp)
    return (
        t.year,
        t.month,
        t.isoweekday() % 7,
        t.day,
        t.hour,
        t.minute,
        t.second,
        int(round(t.microsecond / 1000.0)),
    )


def systemtime_to_timestamp(systemtime):
    try:
        t = datetime.datetime(
            systemtime[0],
            systemtime[1],
            systemtime[3],
            systemtime[4],
            systemtime[5],
            systemtime[6],
            systemtime[7] * 1000,
        )
        return time.mktime(t.timetuple()) + systemtime[7] / 1000.0
    except ValueError:
        return 0


class BLFReader(BaseIOHandler):
    """
    Iterator of CAN messages from a Binary Logging File.

    Only CAN messages and error frames are supported. Other object types are
    silently ignored.
    """

    OBJ_STRUCTS = {
        CAN_MESSAGE: CAN_MSG_STRUCT,
        CAN_ERROR_EXT: CAN_ERROR_EXT_STRUCT,
        CAN_MESSAGE2: CAN_MSG_STRUCT,
        CAN_FD_MESSAGE: CAN_FD_MSG_STRUCT,
        CAN_FD_MESSAGE_64: CAN_FD_MSG_64_STRUCT,
    }

    def __init__(self, file):
        """
        :param file: a path-like object or as file-like object to read from
                     If this is a file-like object, is has to opened in binary
                     read mode, not text read mode.
        """
        super().__init__(file, mode="rb")
        data = self.file.read(FILE_HEADER_STRUCT.size)
        header = FILE_HEADER_STRUCT.unpack(data)
        if header[0] != b"LOGG":
            raise BLFParseError("Unexpected file format")
        self.file_size = header[10]
        self.uncompressed_size = header[11]
        self.object_count = header[12]
        self.start_timestamp = systemtime_to_timestamp(header[14:22])
        self.stop_timestamp = systemtime_to_timestamp(header[22:30])
        # Read rest of header
        self.file.read(header[1] - FILE_HEADER_STRUCT.size)
        self._tail = b""

    def __iter__(self):
        while True:
            data = self.file.read(OBJ_HEADER_BASE_STRUCT.size)
            if not data:
                # EOF
                break

            signature, _, _, obj_size, obj_type = OBJ_HEADER_BASE_STRUCT.unpack(data)
            if signature != b"LOBJ":
                raise BLFParseError()
            obj_data = self.file.read(obj_size - OBJ_HEADER_BASE_STRUCT.size)
            # Read padding bytes
            self.file.read(obj_size % 4)

            if obj_type == LOG_CONTAINER:
                method, uncompressed_size = LOG_CONTAINER_STRUCT.unpack_from(obj_data)
                container_data = memoryview(obj_data)[LOG_CONTAINER_STRUCT.size :]
                if method == NO_COMPRESSION:
                    data = container_data
                elif method == ZLIB_DEFLATE:
                    data = zlib.decompress(container_data, 15, uncompressed_size)
                else:
                    # Unknown compression method
                    LOG.warning("Unknown compression method (%d)", method)
                    continue
                yield from self._parse_container(data)
        self.stop()

    def _parse_container(self, data):
        if self._tail:
            data = b"".join((self._tail, data))
        pos = 0
        while pos + OBJ_HEADER_BASE_STRUCT.size < len(data):
            header = OBJ_HEADER_BASE_STRUCT.unpack_from(data, pos)
            signature, _, header_version, obj_size, obj_type = header
            if signature != b"LOBJ":
                raise BLFParseError()
            # Calculate position of next object
            next_pos = pos + obj_size
            if obj_type != CAN_FD_MESSAGE_64:
                # Add padding bytes
                next_pos += obj_size % 4
            if next_pos > len(data):
                # Object continues in next log container
                break
            if obj_type not in self.OBJ_STRUCTS:
                # Unknown object type, continue to next object
                # LOG.warning("Unknown object type (%d)", obj_type)
                pos = next_pos
                continue
            pos += OBJ_HEADER_BASE_STRUCT.size

            # Read rest of header
            if header_version == 1:
                flags, _, _, timestamp = OBJ_HEADER_V1_STRUCT.unpack_from(data, pos)
                pos += OBJ_HEADER_V1_STRUCT.size
            elif header_version == 2:
                flags, _, _, timestamp, _ = OBJ_HEADER_V2_STRUCT.unpack_from(data, pos)
                pos += OBJ_HEADER_V2_STRUCT.size
            else:
                LOG.warning("Unknown object header version (%d)", header_version)
                pos = next_pos
                continue

            members = self.OBJ_STRUCTS[obj_type].unpack_from(data, pos)
            msg = None
            if obj_type in (CAN_MESSAGE, CAN_MESSAGE2):
                msg = self._parse_can_message(members)
            elif obj_type == CAN_FD_MESSAGE:
                msg = self._parse_can_fd_message(members)
            elif obj_type == CAN_FD_MESSAGE_64:
                pos += CAN_FD_MSG_64_STRUCT.size
                msg = self._parse_can_fd_message_64(members, data[pos : pos + 64])
            elif obj_type == CAN_ERROR_EXT:
                msg = self._parse_can_error_ext(members)

            if msg is not None:
                factor = 1e-5 if flags == TIME_TEN_MICS else 1e-9
                msg.timestamp = timestamp * factor + self.start_timestamp
                yield msg
            pos = next_pos
        # save the remaining data that could not be processed
        self._tail = data[pos:]

    @staticmethod
    def _parse_can_message(members):
        channel, flags, dlc, can_id, can_data = members
        return Message(
            arbitration_id=can_id & 0x1FFFFFFF,
            is_extended_id=bool(can_id & CAN_MSG_EXT),
            is_remote_frame=bool(flags & REMOTE_FLAG),
            dlc=dlc,
            data=can_data[:dlc],
            channel=channel - 1,
        )

    @staticmethod
    def _parse_can_fd_message(members):
        channel, flags, dlc, can_id, _, _, fd_flags, valid_bytes, can_data = members
        return Message(
            arbitration_id=can_id & 0x1FFFFFFF,
            is_extended_id=bool(can_id & CAN_MSG_EXT),
            is_remote_frame=bool(flags & REMOTE_FLAG),
            is_fd=bool(fd_flags & EDL),
            bitrate_switch=bool(fd_flags & BRS),
            error_state_indicator=bool(fd_flags & ESI),
            dlc=dlc2len(dlc),
            data=can_data[:valid_bytes],
            channel=channel - 1,
        )

    @staticmethod
    def _parse_can_fd_message_64(members, data):
        channel, dlc, valid_bytes, _, can_id, _, fd_flags = members[:7]
        return Message(
            arbitration_id=can_id & 0x1FFFFFFF,
            is_extended_id=bool(can_id & CAN_MSG_EXT),
            is_remote_frame=bool(fd_flags & REMOTE_FLAG_64),
            is_fd=bool(fd_flags & EDL_64),
            bitrate_switch=bool(fd_flags & BRS_64),
            error_state_indicator=bool(fd_flags & ESI_64),
            dlc=dlc2len(dlc),
            data=data[:valid_bytes],
            channel=channel - 1,
        )

    @staticmethod
    def _parse_can_error_ext(members):
        channel = members[0]
        dlc = members[5]
        can_id = members[7]
        can_data = members[9]
        return Message(
            is_error_frame=True,
            is_extended_id=bool(can_id & CAN_MSG_EXT),
            arbitration_id=can_id & 0x1FFFFFFF,
            dlc=dlc,
            data=can_data[:dlc],
            channel=channel - 1,
        )


class BLFWriter(BaseIOHandler, Listener):
    """
    Logs CAN data to a Binary Logging File compatible with Vector's tools.
    """

    #: Max log container size of uncompressed data
    MAX_CONTAINER_SIZE = 128 * 1024

    def __init__(
        self, file, append: bool = False, channel: int = 1, compression_level: int = -1
    ):
        """
        :param file: a path-like object or as file-like object to write to
                     If this is a file-like object, is has to opened in mode "wb+".
        :param channel:
            Default channel to log as if not specified by the interface.
        :param append:
            Append messages to an existing log file.
        :param compression_level:
            An integer from 0 to 9 or -1 controlling the level of compression.
            1 (Z_BEST_SPEED) is fastest and produces the least compression.
            9 (Z_BEST_COMPRESSION) is slowest and produces the most.
            0 means that data will be stored without processing.
            The default value is -1 (Z_DEFAULT_COMPRESSION).
            Z_DEFAULT_COMPRESSION represents a default compromise between
            speed and compression (currently equivalent to level 6).
        """
        mode = "rb+" if append else "wb+"
        try:
            super().__init__(file, mode=mode)
        except FileNotFoundError:
            # Trying to append to a non-existing file, create a new one
            append = False
            mode = "wb+"
            super().__init__(file, mode=mode)
        assert self.file is not None
        self.channel = channel
        self.compression_level = compression_level
        self._buffer: List[bytes] = []
        self._buffer_size = 0
        if append:
            data = self.file.read(FILE_HEADER_STRUCT.size)
            header = FILE_HEADER_STRUCT.unpack(data)
            if header[0] != b"LOGG":
                raise BLFParseError("Unexpected file format")
            self.uncompressed_size = header[11]
            self.object_count = header[12]
            self.start_timestamp = systemtime_to_timestamp(header[14:22])
            self.stop_timestamp = systemtime_to_timestamp(header[22:30])
            # Jump to the end of the file
            self.file.seek(0, 2)
        else:
            self.object_count = 0
            self.uncompressed_size = FILE_HEADER_SIZE
            self.start_timestamp = None
            self.stop_timestamp = None
            # Write a default header which will be updated when stopped
            self._write_header(FILE_HEADER_SIZE)
            # Pad to header size
            self.file.write(b"\x00" * (FILE_HEADER_SIZE - FILE_HEADER_STRUCT.size))

    def _write_header(self, filesize):
        # Write header in the beginning of the file
        header = [b"LOGG", FILE_HEADER_SIZE, APPLICATION_ID, 0, 0, 0, 2, 6, 8, 1]
        # The meaning of "count of objects read" is unknown
        header.extend([filesize, self.uncompressed_size, self.object_count, 0])
        header.extend(timestamp_to_systemtime(self.start_timestamp))
        header.extend(timestamp_to_systemtime(self.stop_timestamp))
        self.file.write(FILE_HEADER_STRUCT.pack(*header))

    def on_message_received(self, msg):
        channel = channel2int(msg.channel)
        if channel is None:
            channel = self.channel
        else:
            # Many interfaces start channel numbering at 0 which is invalid
            channel += 1

        arb_id = msg.arbitration_id
        if msg.is_extended_id:
            arb_id |= CAN_MSG_EXT
        flags = REMOTE_FLAG if msg.is_remote_frame else 0
        data = bytes(msg.data)

        if msg.is_error_frame:
            data = CAN_ERROR_EXT_STRUCT.pack(
                channel,
                0,  # length
                0,  # flags
                0,  # ecc
                0,  # position
                len2dlc(msg.dlc),
                0,  # frame length
                arb_id,
                0,  # ext flags
                data,
            )
            self._add_object(CAN_ERROR_EXT, data, msg.timestamp)
        elif msg.is_fd:
            fd_flags = EDL
            if msg.bitrate_switch:
                fd_flags |= BRS
            if msg.error_state_indicator:
                fd_flags |= ESI
            data = CAN_FD_MSG_STRUCT.pack(
                channel,
                flags,
                len2dlc(msg.dlc),
                arb_id,
                0,
                0,
                fd_flags,
                len(data),
                data,
            )
            self._add_object(CAN_FD_MESSAGE, data, msg.timestamp)
        else:
            data = CAN_MSG_STRUCT.pack(channel, flags, msg.dlc, arb_id, data)
            self._add_object(CAN_MESSAGE, data, msg.timestamp)

    def log_event(self, text, timestamp=None):
        """Add an arbitrary message to the log file as a global marker.

        :param str text:
            The group name of the marker.
        :param float timestamp:
            Absolute timestamp in Unix timestamp format. If not given, the
            marker will be placed along the last message.
        """
        try:
            # Only works on Windows
            text = text.encode("mbcs")
        except LookupError:
            text = text.encode("ascii")
        comment = b"Added by python-can"
        marker = b"python-can"
        data = GLOBAL_MARKER_STRUCT.pack(
            0, 0xFFFFFF, 0xFF3300, 0, len(text), len(marker), len(comment)
        )
        self._add_object(GLOBAL_MARKER, data + text + marker + comment, timestamp)

    def _add_object(self, obj_type, data, timestamp=None):
        if timestamp is None:
            timestamp = self.stop_timestamp or time.time()
        if self.start_timestamp is None:
            self.start_timestamp = timestamp
        self.stop_timestamp = timestamp
        timestamp = int((timestamp - self.start_timestamp) * 1e9)
        header_size = OBJ_HEADER_BASE_STRUCT.size + OBJ_HEADER_V1_STRUCT.size
        obj_size = header_size + len(data)
        base_header = OBJ_HEADER_BASE_STRUCT.pack(
            b"LOBJ", header_size, 1, obj_size, obj_type
        )
        obj_header = OBJ_HEADER_V1_STRUCT.pack(TIME_ONE_NANS, 0, 0, max(timestamp, 0))

        self._buffer.append(base_header)
        self._buffer.append(obj_header)
        self._buffer.append(data)
        padding_size = len(data) % 4
        if padding_size:
            self._buffer.append(b"\x00" * padding_size)

        self._buffer_size += obj_size + padding_size
        self.object_count += 1
        if self._buffer_size >= self.MAX_CONTAINER_SIZE:
            self._flush()

    def _flush(self):
        """Compresses and writes data in the buffer to file."""
        if self.file.closed:
            return
        buffer = b"".join(self._buffer)
        if not buffer:
            # Nothing to write
            return
        uncompressed_data = memoryview(buffer)[: self.MAX_CONTAINER_SIZE]
        # Save data that comes after max size to next container
        tail = buffer[self.MAX_CONTAINER_SIZE :]
        self._buffer = [tail]
        self._buffer_size = len(tail)
        if self.compression_level > 0:
            data = zlib.compress(uncompressed_data, self.compression_level)
            method = ZLIB_DEFLATE
        else:
            data = uncompressed_data
            method = NO_COMPRESSION
        obj_size = OBJ_HEADER_BASE_STRUCT.size + LOG_CONTAINER_STRUCT.size + len(data)
        base_header = OBJ_HEADER_BASE_STRUCT.pack(
            b"LOBJ", OBJ_HEADER_BASE_STRUCT.size, 1, obj_size, LOG_CONTAINER
        )
        container_header = LOG_CONTAINER_STRUCT.pack(method, len(uncompressed_data))
        self.file.write(base_header)
        self.file.write(container_header)
        self.file.write(data)
        # Write padding bytes
        self.file.write(b"\x00" * (obj_size % 4))
        self.uncompressed_size += OBJ_HEADER_BASE_STRUCT.size
        self.uncompressed_size += LOG_CONTAINER_STRUCT.size
        self.uncompressed_size += len(uncompressed_data)

    def stop(self):
        """Stops logging and closes the file."""
        self._flush()
        filesize = self.file.tell()
        # Write header in the beginning of the file
        self.file.seek(0)
        self._write_header(filesize)
        super().stop()
