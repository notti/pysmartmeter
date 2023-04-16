from base64 import decode
import binascii
from dataclasses import dataclass
import struct
import enum
import datetime
from time import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import argparse
import csv

logging.basicConfig(level=logging.DEBUG)


class Buffer():
    def __init__(self, buffer=None, byteorder='big'):
        if buffer is None:
            buffer = bytearray()
        self.buffer = buffer
        self.byteorder = byteorder
        if byteorder == 'big':
            self._float = struct.Struct('>f')
            self._double = struct.Struct('>d')
        else:
            self._float = struct.Struct('<f')
            self._double = struct.Struct('<d')

    def __getitem__(self, key):
        return self.buffer[key]

    def __len__(self):
        return len(self.buffer)

    def extend(self, data):
        self.buffer.extend(data)

    def read(self, num: int = 1) -> bytes:
        if len(self.buffer) < num:
            raise ValueError("Not enough data in buffer")
        ret, rest = self.buffer[:num], self.buffer[num:]
        self.buffer = rest
        return ret

    def read_buffer(self, num: int = 1):
        return Buffer(bytearray(self.read(num)), self.byteorder)

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_i8(self) -> int:
        return int.from_bytes(self.read(1), byteorder=self.byteorder, signed=True)

    def read_u16(self) -> int:
        return int.from_bytes(self.read(2), byteorder=self.byteorder, signed=False)

    def read_i16(self) -> int:
        return int.from_bytes(self.read(2), byteorder=self.byteorder, signed=True)

    def read_u32(self) -> int:
        return int.from_bytes(self.read(4), byteorder=self.byteorder, signed=False)

    def read_i32(self) -> int:
        return int.from_bytes(self.read(4), byteorder=self.byteorder, signed=True)

    def read_u64(self) -> int:
        return int.from_bytes(self.read(8), byteorder=self.byteorder, signed=False)

    def read_i64(self) -> int:
        return int.from_bytes(self.read(8), byteorder=self.byteorder, signed=True)

    def read_float(self) -> float:
        return self._float.unpack(self.read(4))

    def read_double(self) -> float:
        return self._double.unpack(self.read(8))

    def read_len(self) -> int:
        l = self.read_u8()
        if l <= 0x80:
            return l
        match l:
            case 0x81:
                return self.read_u8()
            case 0x82:
                return self.read_u16()
            case 0x84:
                return self.read_u32()
        raise ValueError("Bad length")


@enum.unique
class MBusControl(enum.IntEnum):
    SND_UD = 0x53
    # FIXME


def find_frame(buffer: Buffer):
    while buffer:
        if buffer[0] == 0x68 and buffer[3] == 0x68 and buffer[1] == buffer[2]:
            l = buffer[1] + 6
            if len(buffer) < l:
                return None
            return MBusData.from_buffer(buffer)
        buffer.read()  # try next char
    return None


START = 0x68
STOP = 0x16


class MBusTransport():
    def __init__(self, CI: int, STSAP: int, DTSAP: int, inner: Buffer):
        self.fin = bool(CI & 0x10)
        self.seq = CI & 0x0F
        if CI & 0xE:
            raise ValueError("unsupported CI")
        self.STSAP = STSAP
        self.DTSAP = DTSAP
        self.inner = inner

    def __repr__(self) -> str:
        return f"MBusTransport(fin: {self.fin} ({self.seq}); {self.STSAP:02x} {self.DTSAP:02x}: {len(self.inner)})"

    @classmethod
    def from_buffer(cls, buffer: Buffer):
        CI = buffer.read_u8()
        STSAP = buffer.read_u8()
        DTSAP = buffer.read_u8()
        inner = buffer
        return cls(CI, STSAP, DTSAP, inner)


class CipherType(enum.IntEnum):
    GeneralGLO = 0xdb


class MBusData():
    def __init__(self, C: int, A: int, inner: Buffer):
        self.C = MBusControl(C)
        self.A = A
        if self.C == MBusControl.SND_UD:
            inner = MBusTransport.from_buffer(inner)
        else:
            raise NotImplementedError(f"Type {self.C} not supported")
        self.inner = inner

    def __repr__(self) -> str:
        return f"MBusData({self.C!r}, {self.A:02x}; {self.inner})"

    @classmethod
    def from_buffer(cls, buffer: Buffer):
        start = buffer.read_u8()
        if start != START:
            raise ValueError("Not a valid MBus data frame")
        l = buffer.read_u8()
        l2 = buffer.read_u8()
        if l != l2:
            raise ValueError("Not a valid MBus data frame")
        start = buffer.read_u8()
        if start != START:
            raise ValueError("Not a valid MBus data frame")

        C = buffer.read_u8()
        A = buffer.read_u8()
        inner = buffer.read_buffer(l-2)

        chk = buffer.read_u8()
        if chk != (C+A+sum(inner)) % 256:
            raise ValueError("Incorrect checksum")
        stop = buffer.read_u8()

        if stop != STOP:
            raise ValueError("Incorrect stop byte")

        return cls(C, A, inner)

    def decrypt(self):
        if self.C == MBusControl.SND_UD:
            data = self.inner.inner
            cipher_service = CipherType(data.read_u8())
            if cipher_service != CipherType.GeneralGLO:
                raise ValueError("Unknown cipher")
            title_len = data.read_u8()
            if title_len != 8:
                raise ValueError("Bad title length")
            title = data.read(title_len)
            data_len = data.read_len()
            ctrl = data.read_u8()
            seq = data.read(4)
            seq_nr = int.from_bytes(seq, 'big', signed=False)
            if len(data)+5 != data_len:
                raise ValueError("Wrong length")
            iv = title + seq
#            FIXME authenticated:
#            dec = Cipher(algorithm, modes.GCM(bytes(iv)))
#            dec = dec.decryptor()
#            data = dec.update(data.buffer)  # + dec.finalize()
#           unauthenticated GCM (=CTR mode with counter initialized to 2 = iv + [0,0,0,2])
            dec = Cipher(algorithm, modes.CTR(
                bytes(iv + bytearray([0, 0, 0, 2])))).decryptor()
            data = dec.update(data.buffer) + dec.finalize()
            return Buffer(data)
        raise NotImplementedError("Unknown data frame")


class Fragments:
    def __init__(self):
        self.fragments = []

    def frame(self, frame: MBusData) -> MBusData:
        if frame.C == MBusControl.SND_UD:
            if len(self.fragments) != frame.inner.seq:
                logging.error(
                    f"frame out of seq {len(self.fragments)}/{frame}")
                return
            self.fragments.append(frame)
            if frame.inner.fin:
                ret = self.fragments[0]
                for frame in self.fragments[1:]:
                    ret.inner.inner.extend(frame.inner.inner)
                ret.inner.fin = True
                ret.inner.seq = 0
                self.fragments = []
                return ret
            return
        raise NotImplementedError("Unsupported frame type")


class Command(enum.IntEnum):
    DataNotification = 0x0f


class DataBuffer(Buffer):
    def read_datetime(self):
        year = self.read_u16()
        month = self.read_u8()
        day = self.read_u8()
        dayOfWeek = self.read_u8()
        hour = self.read_u8()
        minute = self.read_u8()
        second = self.read_u8()
        ms = self.read_u8()
        deviation = self.read_i16()
        status = self.read_u8()
        return datetime.datetime(year, month, day, hour, minute, second, ms*1000, datetime.timezone(datetime.timedelta(minutes=-deviation)))

    def read_date(self):
        year = self.read_u16()
        month = self.read_u8()
        day = self.read_u8()
        dayOfWeek = self.read_u8()
        return datetime.date(year, month, day)

    def read_time(self):
        hour = self.read_u8()
        minute = self.read_u8()
        second = self.read_u8()
        ms = self.read_u8()
        return datetime.time(hour, minute, second, ms*1000)


class DataType(enum.IntEnum):
    ARRAY = 0x01
    STRUCTURE = 0x02
    BOOLEAN = 0x03
    BITSTRING = 0x04
    INT32 = 0x05
    UINT32 = 0x06
    OCTET_STRING = 0x09
    STRING = 0x0A
    STRING_UTF8 = 0x0C
    BCD = 0x0D
    INT8 = 0x0F
    INT16 = 0x10
    UINT8 = 0x11
    UINT16 = 0x12
    COMPACT_ARRAY = 0x13
    INT64 = 0x14
    UINT64 = 0x15
    ENUM = 0x16
    FLOAT32 = 0x17
    FLOAT64 = 0x18
    DATETIME = 0x19
    DATE = 0x1a
    TIME = 0x1b


class Unit(enum.IntEnum):
    WATT = 27
    VA = 28
    var = 29
    Wh = 30
    VAh = 31
    varh = 32
    A = 33
    C = 34
    V = 35
    COUNT = 255


@dataclass
class Value:
    value: int | float
    typ: Unit


@dataclass
class Tag:
    value: bytes

    @classmethod
    def from_string(cls, value):
        return cls(bytes([int(x) for x in value.split(".")]))

    def __repr__(self) -> str:
        return '.'.join(str(i) for i in self.value)

    def __str__(self) -> str:
        return '.'.join(str(i) for i in self.value)

    def __hash__(self) -> int:
        return hash(self.value)


def decode_data(buffer: DataBuffer):
    typ = DataType(buffer.read_u8())
    match typ:
        case DataType.UINT8:
            return buffer.read_u8()
        case DataType.ENUM:
            return buffer.read_u8()  # FIXME
        case DataType.UINT16:
            return buffer.read_u16()
        case DataType.UINT32:
            return buffer.read_u32()
        case DataType.UINT64:
            return buffer.read_u64()
        case DataType.INT8:
            return buffer.read_i8()
        case DataType.INT16:
            return buffer.read_i16()
        case DataType.INT32:
            return buffer.read_i32()
        case DataType.INT64:
            return buffer.read_i64()
        case DataType.DATE:
            return buffer.read_date()
        case DataType.TIME:
            return buffer.read_time()
        case DataType.DATETIME:
            return buffer.read_datetime()
        case DataType.FLOAT32:
            return buffer.read_float()
        case DataType.FLOAT64:
            return buffer.read_double()
        case DataType.STRING_UTF8 | DataType.STRING:
            l = buffer.read_len()
            return buffer.read(l).decode('utf8')
        case DataType.OCTET_STRING:
            l = buffer.read_len()
            return buffer.read(l)
        case DataType.BOOLEAN:
            return bool(buffer.read_u8())
        case DataType.ARRAY:
            return [decode_data(buffer) for _ in range(buffer.read_len())]
        case DataType.STRUCTURE:
            # FIXME
            return [decode_data(buffer) for _ in range(buffer.read_len())]
    raise NotImplementedError(f"Unknown data type {typ}")


Tags = {
    Tag.from_string("1.0.1.8.0.255"): "+A",
    Tag.from_string("1.0.2.8.0.255"): "-A",
    Tag.from_string("1.0.1.7.0.255"): "+P",
    Tag.from_string("1.0.2.7.0.255"): "-P",
    Tag.from_string("1.0.32.7.0.255"): "UL1",
    Tag.from_string("1.0.52.7.0.255"): "UL2",
    Tag.from_string("1.0.72.7.0.255"): "UL3",
    Tag.from_string("1.0.31.7.0.255"): "IL1",
    Tag.from_string("1.0.51.7.0.255"): "IL2",
    Tag.from_string("1.0.71.7.0.255"): "IL3",
}

RTags = {value: key for key, value in Tags.items()}


@dataclass
class Notification:
    invocationId: int
    time: datetime.time | datetime.date | datetime.datetime
    values: dict[Tag, Value]
    id: bytes

    def __str__(self):
        values = []
        for tag, value in self.values.items():
            if tag in Tags:
                values.append(f"{Tags[tag]}={value.value}{value.typ.name}")
        return f"{self.time}: {', '.join(values)}"


def decode_data_notification(buffer: Buffer):
    buffer = DataBuffer(buffer)
    invokeId = buffer.read_u32()
    time_l = buffer.read_u8()
    time = None
    match time_l:
        case 4:
            time = buffer.read_time()
        case 5:
            time = buffer.read_date()
        case 12:
            time = buffer.read_datetime()
    _, *data, id = decode_data(buffer)
    return Notification(invokeId, time, {Tag(data[i*3]): Value(data[i*3+1]*10**data[i*3+2][0], Unit(data[i*3+2][1]))
                                         for i in range(len(data)//3)}, id)


def decode_pdu(buffer: Buffer):
    cmd = Command(buffer.read_u8())
    if cmd != Command.DataNotification:
        raise NotImplementedError("Can only do data notifications")
    return decode_data_notification(buffer)


def main():
    parser = argparse.ArgumentParser("cosem")
    parser.add_argument("--timescaledb", nargs='?')
    parser.add_argument("--out", type=argparse.FileType('w'), nargs='?')
    parser.add_argument("--out-values", nargs='?',
                        default='+A,+P,UL1,UL2,UL3,IL1,IL2,IL3')
    parser.add_argument("key", type=argparse.FileType('r'))
    parser.add_argument("data", type=argparse.FileType('r'), nargs='?')

    res = parser.parse_args()

    global algorithm
    algorithm = algorithms.AES128(binascii.unhexlify(res.key.read()))
    res.key.close()

    wr = None
    if res.out is not None:
        wr = csv.writer(res.out, dialect='excel')
        wr.writerow(["time"] + res.out_values.split(','))
    out_values = res.out_values.split(',')

    timescaledb = None
    if res.timescaledb is not None:
        import psycopg2

        conn = psycopg2.connect(res.timescaledb)
        timescaledb = conn.cursor()

    frags = Fragments()
    if res.data is not None:
        for line in res.data.readlines():
            line = Buffer(binascii.unhexlify(line.strip()))
            while line:
                frame = find_frame(line)
                frame = frags.frame(frame)
                if frame is not None:
                    pdu = decode_pdu(frame.decrypt())
                    logging.info(pdu)
                    if wr is not None:
                        wr.writerow([str(int(pdu.time.timestamp()))] +
                                    [pdu.values[RTags[value]].value for value in out_values])
                    if timescaledb is not None:
                        timescaledb.execute(
                            r"""INSERT INTO smartmeter(time, Ain, Pin, UL1, UL2, UL3, IL1, IL2, IL3) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            [pdu.time]+[pdu.values[RTags[value]].value for value in ['+A', '+P', 'UL1', 'UL2', 'UL3', 'IL1', 'IL2', 'IL3']])
    else:
        import serial

        ser = serial.Serial("/dev/ttyAMA0", baudrate=2400,
                            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE)

        buffer = Buffer()

        while 1:
            buffer.extend(ser.read_until(expected=b'\x16'))
            frame = find_frame(buffer)
            if frame is not None:
                frame = frags.frame(frame)
                if frame is not None:
                    pdu = decode_pdu(frame.decrypt())
                    logging.info(pdu)
                    if wr is not None:
                        wr.writerow([str(int(pdu.time.timestamp()))] +
                                    [pdu.values[RTags[value]].value for value in out_values])
                    if timescaledb is not None:
                        timescaledb.execute(
                            r"""INSERT INTO smartmeter(time, Ain, Pin, UL1, UL2, UL3, IL1, IL2, IL3) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                            [pdu.time]+[pdu.values[RTags[value]].value for value in ['+A', '+P', 'UL1', 'UL2', 'UL3', 'IL1', 'IL2', 'IL3']])
    if res.out is not None:
        res.out.close()
    if timescaledb is not None:
        conn.commit()


main()
