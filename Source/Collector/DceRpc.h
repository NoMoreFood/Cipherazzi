#pragma once

#include "Model.h"
#include "Json.h"

namespace Cipherazzi
{
// Reads one complete connection-oriented DCE/RPC PDU; bind and alter-context PDUs yield authentication evidence.
bool parseRpcBind(Bytes pdu, Json& fields);
}
