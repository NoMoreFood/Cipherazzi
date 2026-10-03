#pragma once

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace Cipherazzi::FileSecurity
{
inline void require(bool success, const char* operation)
{
    if (!success)
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), operation);
}

inline void protect(const std::filesystem::path& path, bool directory)
{
    // Administrators and SYSTEM can write; ordinary users can read the journal and run the viewer.
    const auto attributes = GetFileAttributesW(path.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES, "Inspect installation path");
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) || bool(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory)
        throw std::runtime_error("Installation paths must be ordinary files and directories");
    PSECURITY_DESCRIPTOR raw = nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(directory ?
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)" :
        L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)", SDDL_REVISION_1, &raw, nullptr), "Build permissions");
    std::unique_ptr<void, decltype(&LocalFree)> security(raw, LocalFree);
    PACL acl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    require(GetSecurityDescriptorDacl(raw, &present, &acl, &defaulted) != FALSE, "Read permissions");
    const auto error = SetNamedSecurityInfoW(const_cast<PWSTR>(path.c_str()), SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
    if (error)
        throw std::system_error(static_cast<int>(error), std::system_category(), "Apply permissions");
}

// A directory that an unprivileged account created stays under that account's control whatever permissions are
// applied afterwards, and so does anything it left inside for the service to open.
inline void requireAdministrativeOwner(const std::filesystem::path& path)
{
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Existing journal paths must be ordinary files and directories");
    const auto error = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner,
        nullptr, nullptr, nullptr, &raw);
    std::unique_ptr<void, decltype(&LocalFree)> descriptor(raw, LocalFree);
    if (error || !owner ||
        (!IsWellKnownSid(owner, WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner, WinLocalSystemSid)))
        throw std::runtime_error("The existing journal directory holds an item that Administrators do not own. "
            "Remove it or assign it to Administrators, then install again");
}

inline void requireAdministrativeWrites(const std::filesystem::path& path)
{
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR raw = nullptr;
    const auto error = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &acl, nullptr, &raw);
    std::unique_ptr<void, decltype(&LocalFree)> descriptor(raw, LocalFree);
    if (error || !acl)
        throw std::runtime_error("Could not verify existing journal permissions");

    // Preserve private credential ACLs while rejecting items an ordinary account can modify or replace.
    constexpr ACCESS_MASK writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
        FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD index = 0; index < acl->AceCount; ++index)
    {
        void* rawAce = nullptr;
        require(GetAce(acl, index, &rawAce) != FALSE, "Read journal permissions");
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
        if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
            continue;
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ((ace->Mask & writes) &&
            !IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinBuiltinAdministratorsSid) &&
            !IsWellKnownSid(const_cast<DWORD*>(&ace->SidStart), WinLocalSystemSid)))
            throw std::runtime_error(
                "Existing journal items must grant write access only to Administrators and SYSTEM");
    }
}

inline void prepareJournalDirectory(const std::filesystem::path& directory)
{
    if (!directory.is_absolute())
        throw std::runtime_error("The journal directory must be an absolute path");
    const bool existing = !std::filesystem::create_directory(directory);
    if (existing)
        requireAdministrativeOwner(directory);
    protect(directory, true);

    // Ordinary users can no longer add to the directory, so validate its existing children.
    size_t entries = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory))
    {
        if (++entries > 4096)
            throw std::runtime_error("The existing journal directory holds too many items to verify");
        requireAdministrativeOwner(entry.path());
        requireAdministrativeWrites(entry.path());
    }
}
}
