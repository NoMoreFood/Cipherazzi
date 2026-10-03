#pragma once

#include "Crypto.h"

namespace Cipherazzi
{
// Total encoded size of a Kerberos message (tag, length, and content) read from its first bytes; zero if implausible.
// `incomplete` is set when a plausible prefix ends before its length does.
size_t kerberosMessageSize(Bytes prefix, bool* incomplete = nullptr);

// One DER-encoded Kerberos message; evidence is published only after the whole message is valid.
bool parseKerberos(Bytes message, nlohmann::json& fields);

// Size declared by a Kerberos change-password message (RFC 3244) read from its first bytes; zero if implausible.
size_t passwordMessageSize(Bytes prefix, bool* incomplete = nullptr);

// One change-password request or reply; the new password and the result of a completed change stay encrypted.
bool parsePasswordChange(Bytes message, nlohmann::json& fields);

// An SMB2 security buffer (SPNEGO, Kerberos, or NTLMSSP); undecodable tokens are flagged, never fatal.
void parseSecurityBuffer(Bytes buffer, bool response, nlohmann::json& fields);
}
