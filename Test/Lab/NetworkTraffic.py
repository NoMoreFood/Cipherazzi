import argparse
import json
import random
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def fragmented_hello(source, destination):
    name = b"fragmented.ipv4.network.lab"
    names = b"\0" + struct.pack("!H", len(name)) + name
    sni = struct.pack("!H", len(names)) + names
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    body = b"\xfe\xfd" + b"B" * 32 + b"\0\0\0\2\xc0\x2f\1\0" + struct.pack("!H", len(extensions)) + extensions
    handshake = b"\1" + len(body).to_bytes(3, "big") + b"\0\0\0\0\0" + len(body).to_bytes(3, "big") + body
    record = b"\x16\xfe\xfd" + b"\0" * 8 + struct.pack("!H", len(handshake)) + handshake
    datagram = struct.pack("!HHHH", 33400, 24629, len(record) + 8, 0) + record
    packets = []
    identity = random.randrange(1, 65535)
    for offset in range(0, len(datagram), 24):
        payload = datagram[offset:offset + 24]
        flags = offset // 8 | (0x2000 if offset + 24 < len(datagram) else 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(payload) + 20, identity, flags, 64, 17, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        packets.append(ip + payload)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        order = list(reversed(packets))
        order.insert(1, order[0])
        for packet in order:
            raw.sendto(packet, (destination, 0))
            time.sleep(0.03)
    print(json.dumps({"fragments_sent": len(order), "sni": name.decode()}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    fragmented_hello(args.source, args.destination)
