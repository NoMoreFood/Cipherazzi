"""Writes a replay capture of Kerberos change-password, large Kerberos, TDS, SMB1, SSL 2.0, and LDAP exchanges.

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

# A self-signed 1024-bit RSA certificate generated with OpenSSL, as an SSL 2.0 server would present.
SERVER_CERTIFICATE = bytes.fromhex(
    "3082021830820181a00302010202146ed8d2774ebae0403bf6682fa08c164684b1f28f300d06092a864886f70d0101050500"
    "301e311c301a06035504030c136c65676163792e6578616d706c652e74657374301e170d3236313031323230343331365a17"
    "0d3436313030373230343331365a301e311c301a06035504030c136c65676163792e6578616d706c652e7465737430819f30"
    "0d06092a864886f70d010101050003818d0030818902818100d485d83fb9a02c345c8c701a3ae55449c150b7296ec93e16d6"
    "9ae133b8ec561e20a1eab6de64758a75dc07ad4e7204e6c1618b4b086046772df49e21ff40e385549bd32bfef9fbbc3b7baa"
    "6a2411db013f86ff50e4017e67e507c142deee112ea1af0767ea7fb32fe6a6f7977ec2f1d98e0da3f501282a5cf3d4a5a698"
    "58c8050203010001a3533051301d0603551d0e041604145857861614f06f0d60b6dde62272a968efb0db98301f0603551d23"
    "0418301680145857861614f06f0d60b6dde62272a968efb0db98300f0603551d130101ff040530030101ff300d06092a8648"
    "86f70d0101050500038181000a9872cdf9508fce5081b853a21bed48aefde427a138711a9fe66dac38efb7dc32db5298a51e"
    "3d5b966ec87d196593fac49eece5a883bbb346b346b10de1683049cc5bb2a66def342b6bcdb493c39f1d9e2eb7116cc6f142"
    "c260ebc0a9c78e0b8066224e6968976c3bb90dc3da53ac112e883930f1b65cc348c3167a306f2e8b")


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


def smb1(response, parameters, data, command=0x72):
    header = (b"\xffSMB" + bytes([command]) + bytes(4) + bytes([0x98 if response else 0x18]) +
              b"\x01\xc8").ljust(32, b"\0")
    return framed(header + bytes([len(parameters) // 2]) + parameters + struct.pack("<H", len(data)) + data)


def session_setup(insensitive, sensitive, account):
    # AndX fields, buffer limits, and both password lengths precede the passwords (MS-CIFS 2.2.4.53.1).
    parameters = struct.pack("<BBHHHHIHHII", 0xFF, 0, 0, 4356, 50, 1, 0, len(insensitive), len(sensitive), 0, 0xD4)
    passwords = insensitive + sensitive
    names = b"".join(text.encode("utf-16-le") + b"\0\0" for text in (account, "WORKGROUP", "Unix", "Samba"))
    return smb1(False, parameters, passwords + bytes(len(passwords) % 2 == 0) + names, 0x73)


def ssl2(message):
    # Each cleartext message follows a two-byte length whose high bit is set.
    return struct.pack(">H", 0x8000 | len(message)) + message


def ssl2_client_hello(version, specs):
    challenge = bytes(range(16))
    return ssl2(struct.pack(">BHHHH", 1, version, len(specs), 0, len(challenge)) + specs + challenge)


def ssl2_server_hello(certificate, specs):
    # No session-ID hit, an X.509 certificate, the server's cipher kinds, and its connection ID.
    connection = bytes(range(16, 32))
    return ssl2(struct.pack(">BBBHHHH", 4, 0, 1, 2, len(certificate), len(specs), len(connection)) +
                certificate + specs + connection)


def ssl2_master_key(kind, clear, encrypted):
    return ssl2(struct.pack(">B3sHHH", 2, kind, len(clear), len(encrypted), 0) + clear + encrypted)


def tls_record(kind, payload):
    return struct.pack(">BHH", kind, 0x0301, len(payload)) + payload


def tls_server_hello(cipher):
    body = struct.pack(">H", 0x0301) + bytes(range(32)) + b"\0" + struct.pack(">HB", cipher, 0)
    return tls_record(22, b"\x02" + len(body).to_bytes(3, "big") + body)


def tls_client_hello(ciphers):
    body = (struct.pack(">H", 0x0301) + bytes(range(32)) + b"\0" + struct.pack(">H", len(ciphers)) + ciphers +
            b"\x01\0")
    return tls_record(22, b"\x01" + len(body).to_bytes(3, "big") + body)


def ber(tag, content):
    # Windows writes every LDAP length in four bytes, which BER permits and DER does not.
    return bytes([tag, 0x84]) + len(content).to_bytes(4, "big") + content


def ldap(message_id, operation):
    return ber(0x30, integer(message_id) + operation)


def ldap_bind(name, authentication):
    return ber(0x60, integer(3) + der(4, name) + authentication)


def ldap_sasl(mechanism, credentials):
    return der(0xA3, der(4, mechanism) + der(4, credentials))


def ldap_result(tag, code, extra=b""):
    # A result code, an empty matched name, and empty diagnostic text precede anything a response adds.
    return ber(tag, der(0x0A, bytes([code])) + der(4, b"") + der(4, b"") + extra)


def ntlm(kind, flags, header, *values):
    # Each value is described by its length, maximum length, and offset, and follows the fixed header (MS-NLMP 2.2).
    descriptors = payload = b""
    for value in values:
        descriptors += struct.pack("<HHI", len(value), len(value), header + len(payload))
        payload += value
    if kind == 1:
        return b"NTLMSSP\0" + struct.pack("<II", kind, flags) + bytes(16)
    if kind == 2:
        return (b"NTLMSSP\0" + struct.pack("<I", kind) + descriptors + struct.pack("<I", flags) + bytes(range(8)) +
                bytes(16) + payload)
    return b"NTLMSSP\0" + struct.pack("<I", kind) + descriptors + struct.pack("<I", flags) + payload


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

    # SMB1 session setups: LM and NTLMv1 responses, then a password sent to a server without challenge/response.
    accepted = smb1(True, struct.pack("<BBHH", 0xFF, 0, 0, 0), b"", 0x73)
    capture.tcp(client, server, 42041, 445, [
        (True, smb1(False, b"", dialects)), (False, smb1(True, bytes(parameters), bytes([7]) * 14)),
        (True, session_setup(bytes([0x31]) * 24, bytes([0x32]) * 24, "alice")), (False, accepted)])
    parameters[2] = 1
    capture.tcp(client, server, 42042, 445, [
        (True, smb1(False, b"", dialects)), (False, smb1(True, bytes(parameters), bytes([7]) * 14)),
        (True, session_setup(b"correct horse\0", b"", "alice")), (False, accepted)])

    # SSL 2.0: the client chooses a full-strength cipher, then an export one whose key is mostly sent in clear.
    rc4, export, triple_des = (bytes.fromhex(kind) for kind in ("010080", "020080", "0700c0"))
    protected = ssl2(bytes([0x9D]) * 48)
    for client_port, kind, clear in ((42050, rc4, 0), (42051, export, 11)):
        capture.tcp(client, server, client_port, 443, [
            (True, ssl2_client_hello(2, triple_des + rc4 + export)),
            (False, ssl2_server_hello(SERVER_CERTIFICATE, rc4 + export)),
            (True, ssl2_master_key(kind, bytes(clear), bytes([0x4B]) * 128)), (True, protected), (False, protected)])

    # A hello in SSL 2.0 format that also offers TLS 1.0, which the server selects and answers in TLS records.
    capture.tcp(client, server, 42052, 443, [
        (True, ssl2_client_hello(0x0301, bytes.fromhex("00000400000a") + rc4)), (False, tls_server_hello(4)),
        (True, tls_record(22, bytes.fromhex("100000020000")) + tls_record(20, b"\x01") +
               tls_record(22, bytes([0x9D]) * 40))])

    # LDAP: a simple bind sends its password as is, and nothing protects the searches that follow.
    search = ber(0x63, der(4, b"") + der(0x0A, b"\0") + der(0x0A, b"\0") + integer(0) + integer(0) + der(1, b"\0") +
                 der(0x87, b"objectClass") + der(0x30, b""))
    capture.tcp(client, server, 42060, 389, [
        (True, ldap(1, ldap_bind(b"cn=backup,dc=example,dc=test", der(0x80, b"correct horse")))),
        (False, ldap(1, ldap_result(0x61, 0))), (True, ldap(2, search)), (False, ldap(2, ldap_result(0x65, 0)))])

    # NTLMv1 inside GSS-SPNEGO binds, first with no security layer afterwards and then with a sealed one.
    names = [text.encode("utf-16-le") for text in ("EXAMPLE", "alice", "WORKSTATION")]
    exchange = [
        (True, ldap(1, ldap_bind(b"", ldap_sasl(b"GSS-SPNEGO", ntlm(1, 0x8201, 32))))),
        (False, ldap(1, ldap_result(0x61, 14, der(0x87, ntlm(2, 0x8201, 48, names[0]))))),
        (True, ldap(2, ldap_bind(b"", ldap_sasl(b"GSS-SPNEGO", ntlm(
            3, 0x8201, 64, bytes([0x31]) * 24, bytes([0x32]) * 24, *names, b""))))),
        (False, ldap(2, ldap_result(0x61, 0)))]
    sealed = struct.pack("<I", 1) + bytes(range(12)) + bytes([0x9D]) * 60
    capture.tcp(client, server, 42061, 389, exchange + [(True, ldap(3, search))])
    capture.tcp(client, server, 42062, 389, exchange + [(True, struct.pack(">I", len(sealed)) + sealed)])

    # StartTLS: the extended operation is answered and TLS 1.0 hellos follow on the same connection.
    start_tls = b"1.3.6.1.4.1.1466.20037"
    capture.tcp(client, server, 42063, 389, [
        (True, ldap(1, ber(0x77, der(0x80, start_tls)))), (False, ldap(1, ldap_result(0x78, 0, der(0x8A, start_tls)))),
        (True, tls_client_hello(bytes.fromhex("002f0035000a"))), (False, tls_server_hello(0x2F))])
    capture.write(arguments.output)


if __name__ == "__main__":
    main()
