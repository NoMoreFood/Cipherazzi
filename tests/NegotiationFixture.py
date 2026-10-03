"""Writes a replay capture of Kerberos change-password, large Kerberos, TDS, and SMB1 exchanges.

The messages are encoded here rather than by the native test builders, so replaying the capture checks the
collector against a second encoder. Replay the result with the collector and inspect it with
`--protocol-ui <db> <output> --negotiation`.
"""
import argparse
import struct

# A recorded MIT Kerberos AS request, including its TCP length prefix.
AS_REQUEST = bytes.fromhex(
    "000000b96a81b63081b3a103020105a20302010aa31a3018300aa10402020096a2020400300aa10402020095a2020400a4"
    "818a308187a00703050000000010a1123010a003020101a10930071b05616c696365a20e1b0c4558414d504c452e544553"
    "54a321301fa003020102a11830161b066b72627467741b0c4558414d504c452e54455354a511180f323032363130313032"
    "33353131305aa70602044646428ba81a301802011202011102011402011302011002011702011902011a")
REALM = b"EXAMPLE.TEST"


def der(tag, content):
    size = len(content)
    if size < 128:
        return bytes([tag, size]) + content
    length = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def integer(value):
    return der(2, value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True))


def context(index, inner):
    return der(0xA0 | index, inner)


def sequence(*parts):
    return der(0x30, b"".join(parts))


def principal(*parts):
    return sequence(context(0, integer(1)), context(1, sequence(*[der(0x1B, part.encode()) for part in parts])))


def encrypted(etype, size):
    cipher = bytes((index * 7 + 3) & 0xFF for index in range(size))
    return sequence(context(0, integer(etype)), context(1, integer(2)), context(2, der(4, cipher)))


def ticket(etype, *service, size=120):
    return der(0x61, sequence(context(0, integer(5)), context(1, der(0x1B, REALM)),
                              context(2, principal(*service)), context(3, encrypted(etype, size))))


def ap_request(ticket_etype, authenticator_etype):
    return der(0x6E, sequence(context(0, integer(5)), context(1, integer(14)), context(2, der(3, bytes(5))),
                              context(3, ticket(ticket_etype, "kadmin", "changepw")),
                              context(4, encrypted(authenticator_etype, 90))))


def ap_reply(etype):
    return der(0x6F, sequence(context(0, integer(5)), context(1, integer(15)), context(2, encrypted(etype, 50))))


def private_message(etype):
    return der(0x75, sequence(context(0, integer(5)), context(1, integer(21)), context(3, encrypted(etype, 70))))


def error(code, data):
    return der(0x7E, sequence(context(0, integer(5)), context(1, integer(30)),
                              context(4, der(0x18, b"20261010120000Z")), context(5, integer(4242)),
                              context(6, integer(code)), context(9, der(0x1B, REALM)),
                              context(10, principal("kadmin", "changepw")),
                              context(11, der(0x1B, b"request refused")), context(12, der(4, data))))


def password_message(version, exchange, protected):
    return struct.pack(">HHH", 6 + len(exchange) + len(protected), version, len(exchange)) + exchange + protected


def as_reply(cipher):
    return der(0x6B, sequence(context(0, integer(5)), context(1, integer(11)), context(3, der(0x1B, REALM)),
                              context(4, principal("alice")),
                              context(5, ticket(23, "krbtgt", REALM.decode(), size=cipher)),
                              context(6, encrypted(18, 200))))


def framed(message):
    return struct.pack(">I", len(message)) + message


def tds(kind, payload):
    return struct.pack(">BBHHBB", kind, 1, len(payload) + 8, 0, 1, 0) + payload


def prelogin(encryption):
    # VERSION, ENCRYPTION, and MARS option tokens precede their values (MS-TDS 2.2.6.5).
    options = b"".join(bytes([token]) + struct.pack(">HH", offset, size)
                       for token, offset, size in ((0, 16, 6), (1, 22, 1), (4, 23, 1)))
    return options + b"\xff" + bytes([16, 0, 0x18, 0x42, 0, 0, encryption, 0])


def smb1(response, parameters, data):
    header = (b"\xffSMB\x72" + bytes(4) + bytes([0x98 if response else 0x18]) + b"\x01\xc8").ljust(32, b"\0")
    return framed(header + bytes([len(parameters) // 2]) + parameters + struct.pack("<H", len(data)) + data)


class Capture:
    def __init__(self):
        self.packets = []

    def add(self, source, destination, protocol, payload):
        self.packets.append(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, protocol, 0,
                                        bytes(source), bytes(destination)) + payload)

    def udp(self, source, destination, source_port, destination_port, payload):
        self.add(source, destination, 17,
                 struct.pack(">HHHH", source_port, destination_port, 8 + len(payload), 0) + payload)

    def tcp(self, client, server, client_port, server_port, exchange):
        sequence_numbers = {True: 1000, False: 9000}

        def segment(from_client, flags, payload=b""):
            source, destination = (client, server) if from_client else (server, client)
            ports = (client_port, server_port) if from_client else (server_port, client_port)
            self.add(source, destination, 6, struct.pack(
                ">HHIIBBHHH", *ports, sequence_numbers[from_client], sequence_numbers[not from_client], 0x50,
                flags, 65535, 0, 0) + payload)
            sequence_numbers[from_client] += len(payload) + (1 if flags & 3 else 0)

        segment(True, 0x02)
        segment(False, 0x12)
        segment(True, 0x10)
        for from_client, payload in exchange:
            for offset in range(0, len(payload), 1460):
                segment(from_client, 0x18, payload[offset:offset + 1460])
        segment(True, 0x11)
        segment(False, 0x11)

    def write(self, path):
        with open(path, "wb") as output:
            output.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
            for index, packet in enumerate(self.packets):
                output.write(struct.pack("<IIII", 1791633600 + index // 1000, index % 1000 * 1000,
                                         len(packet), len(packet)))
                output.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    arguments = parser.parse_args()
    client, server = (192, 0, 2, 1), (192, 0, 2, 2)
    capture = Capture()

    # Change-password over UDP: a completed version 1 change and a refused set-password request.
    change = password_message(1, ap_request(18, 18), private_message(18))
    capture.udp(client, server, 42001, 464, change)
    capture.udp(server, client, 464, 42001, password_message(1, ap_reply(18), private_message(18)))
    capture.udp(client, server, 42002, 464, password_message(0xFF80, ap_request(23, 17), private_message(23)))
    capture.udp(server, client, 464, 42002, password_message(1, b"", error(60, b"\x00\x05Access denied")))

    # The same change over TCP on the registered port and on another one.
    for client_port, server_port in ((42010, 464), (42011, 10464)):
        capture.tcp(client, server, client_port, server_port, [
            (True, framed(change)), (False, framed(password_message(1, ap_reply(17), private_message(17))))])

    # An AS exchange whose reply exceeds 64 KiB and arrives in MSS-sized segments.
    capture.tcp(client, server, 42020, 88, [(True, AS_REQUEST), (False, framed(as_reply(70000)))])

    # TDS: an unencrypted login, login-only encryption, a server requirement, and incompatible settings.
    capture.tcp(client, server, 42030, 1433, [
        (True, tds(0x12, prelogin(2))), (False, tds(4, prelogin(2))), (True, tds(0x10, b"L" * 94))])
    for client_port, offer, answer in ((42031, 0, 0), (42032, 0x80, 3), (42033, 1, 2)):
        capture.tcp(client, server, client_port, 1433, [
            (True, tds(0x12, prelogin(offer))), (False, tds(4, prelogin(answer)))])

    # SMB1: an NT LM 0.12 response selects the third offered dialect.
    dialects = b"".join(b"\x02" + name + b"\0" for name in (b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0", b"NT LM 0.12"))
    parameters = bytearray(34)
    parameters[0], parameters[2], parameters[33] = 2, 3, 8
    parameters[19:23] = struct.pack("<I", 0x400)
    capture.tcp(client, server, 42040, 445, [
        (True, smb1(False, b"", dialects)), (False, smb1(True, bytes(parameters), bytes([7]) * 14))])
    capture.write(arguments.output)


if __name__ == "__main__":
    main()
