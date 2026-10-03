#include "../../src/shared/FileSecurity.h"
#include <fstream>
#include <string>
#include <vector>

namespace Cipherazzi::Tests
{
void require(bool result, const char* message);

void installationDirectoryCoverage()
{
    // Exercise the shared CLI/MSI guard against an existing user-owned journal in a disposable directory.
    const auto directory = std::filesystem::temp_directory_path() /
        (L"Cipherazzi-installation-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
            std::to_wstring(GetTickCount64()));
    std::filesystem::create_directory(directory);
    const auto journal = directory / L"capture.db";
    std::ofstream(journal) << "Existing journal";
    HANDLE rawToken = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken), "Read test identity");
    std::unique_ptr<void, decltype(&CloseHandle)> token(rawToken, CloseHandle);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> user(size);
    require(GetTokenInformation(token.get(), TokenUser, user.data(), size, &size), "Read test user");
    const auto userSid = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
    require(SetNamedSecurityInfoW(const_cast<PWSTR>(journal.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, userSid, nullptr, nullptr, nullptr) == ERROR_SUCCESS,
        "Assign journal ownership to the current user");
    bool rejected = false;
    try { FileSecurity::prepareJournalDirectory(directory); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "Installation accepted a user-owned existing journal");
    std::string contents;
    std::getline(std::ifstream(journal), contents);
    require(contents == "Existing journal", "Rejected installation changed the journal");

    // Administrative ownership alone does not prevent explicit user grants from modifying service data.
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)", SDDL_REVISION_1, &raw, nullptr),
        "Create writable journal permissions");
    std::unique_ptr<void, decltype(&LocalFree)> security(raw, LocalFree);
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted), "Read writable journal permissions");
    require(SetNamedSecurityInfoW(const_cast<PWSTR>(journal.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) ==
        ERROR_SUCCESS,
        "Assign writable journal permissions");
    rejected = false;
    try { FileSecurity::requireAdministrativeWrites(journal); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "Journal permissions accepted ordinary-user write access");
    FileSecurity::protect(journal, false);
    FileSecurity::requireAdministrativeWrites(journal);

    // An elevated test also verifies an administrator-owned directory and reparse-point rejection.
    TOKEN_ELEVATION elevation{};
    require(GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &size),
        "Read test elevation");
    if (elevation.TokenIsElevated)
    {
        BYTE administrators[SECURITY_MAX_SID_SIZE]{};
        size = sizeof(administrators);
        require(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &size),
            "Create administrator identity");
        for (const auto& path : {directory, journal})
            require(SetNamedSecurityInfoW(const_cast<PWSTR>(path.c_str()), SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION, administrators, nullptr, nullptr, nullptr) == ERROR_SUCCESS,
                "Assign administrator ownership");
        FileSecurity::prepareJournalDirectory(directory);
        const auto nested = directory / L"nested";
        std::filesystem::create_directory(nested);
        const auto untrusted = nested / L"capture.db";
        std::ofstream(untrusted) << "Untrusted nested journal";
        require(SetNamedSecurityInfoW(const_cast<PWSTR>(untrusted.c_str()), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION, userSid, nullptr, nullptr, nullptr) == ERROR_SUCCESS,
            "Assign nested journal ownership");
        rejected = false;
        try { FileSecurity::prepareJournalDirectory(directory); }
        catch (const std::runtime_error&) { rejected = true; }
        require(rejected, "Installation accepted an untrusted nested journal");
        std::filesystem::remove(untrusted);
        std::filesystem::remove(nested);
        const auto link = directory / L"capture-link.db";
        if (CreateSymbolicLinkW(link.c_str(), journal.c_str(), SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
        {
            rejected = false;
            try { FileSecurity::prepareJournalDirectory(directory); }
            catch (const std::runtime_error&) { rejected = true; }
            require(rejected, "Installation accepted a journal reparse point");
            std::filesystem::remove(link);
        }
    }
    std::filesystem::remove(journal);
    std::filesystem::remove(directory);
}
}
