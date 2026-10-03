#include "../../src/shared/FileSecurity.h"
#include <msi.h>
#include <msiquery.h>
#include <string>

namespace Cipherazzi::Installer
{
std::wstring data(MSIHANDLE installation)
{
    std::wstring value(32768, L'\0');
    DWORD length = static_cast<DWORD>(value.size());
    if (MsiGetPropertyW(installation, L"CustomActionData", value.data(), &length) != ERROR_SUCCESS || !length)
        throw std::runtime_error("The installation action has no valid configuration");
    value.resize(length);
    return value;
}

UINT failure(MSIHANDLE installation, const std::exception& error)
{
    PMSIHANDLE record = MsiCreateRecord(1);
    MsiRecordSetStringW(record, 0, L"Cipherazzi installation failed: [1]");
    MsiRecordSetStringA(record, 1, error.what());
    MsiProcessMessage(installation, INSTALLMESSAGE_ERROR, record);
    return ERROR_INSTALL_FAILURE;
}
}

extern "C" __declspec(dllexport) UINT __stdcall PrepareJournalDirectory(MSIHANDLE installation)
{
    // Reject untrusted existing files before Windows Installer can replace the directory's owner.
    try
    {
        Cipherazzi::FileSecurity::prepareJournalDirectory(Cipherazzi::Installer::data(installation));
        return ERROR_SUCCESS;
    }
    catch (const std::exception& error)
    {
        return Cipherazzi::Installer::failure(installation, error);
    }
}

extern "C" __declspec(dllexport) UINT __stdcall ConfigureServiceRecovery(MSIHANDLE installation)
{
    // Configure handled-error recovery during installation; workers need no service configuration rights.
    try
    {
        using Manager = std::unique_ptr<std::remove_pointer_t<SC_HANDLE>, decltype(&CloseServiceHandle)>;
        const auto name = Cipherazzi::Installer::data(installation);
        Manager manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT), CloseServiceHandle);
        Cipherazzi::FileSecurity::require(bool(manager), "Open service manager");
        Manager service(OpenServiceW(manager.get(), name.c_str(), SERVICE_CHANGE_CONFIG), CloseServiceHandle);
        Cipherazzi::FileSecurity::require(bool(service), "Open installed service");
        SERVICE_FAILURE_ACTIONS_FLAG flag{TRUE};
        Cipherazzi::FileSecurity::require(
            ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag),
            "Configure service recovery");
        return ERROR_SUCCESS;
    }
    catch (const std::exception& error)
    {
        return Cipherazzi::Installer::failure(installation, error);
    }
}
