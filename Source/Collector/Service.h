#pragma once

#include <atomic>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace Cipherazzi
{
enum class ServicePhase { Starting, Running, Stopping };

std::filesystem::path serviceDatabase();
void installService(const std::vector<std::wstring>& arguments);
void uninstallService();
int runService(std::atomic<bool>& stopped, std::function<void()> work);
void serviceProgress(ServicePhase phase);
}
