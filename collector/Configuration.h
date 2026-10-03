#pragma once

#include <span>
#include <string>
#include <vector>

namespace Cipherazzi
{
std::vector<std::wstring> configurationArguments(std::span<wchar_t*> arguments);
}
