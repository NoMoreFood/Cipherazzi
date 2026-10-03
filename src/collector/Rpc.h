#pragma once

#include "Model.h"
#include <nlohmann/json.hpp>

namespace Cipherazzi
{
// Reads one complete connection-oriented DCE/RPC PDU; bind and alter-context PDUs yield authentication evidence.
bool parseRpcBind(Bytes pdu, nlohmann::json& fields);
}
