import argparse
import contextlib
import ctypes
import hashlib
import itertools
import json
import struct
from pathlib import Path
from ctypes import wintypes


msi = ctypes.WinDLL("msi")
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
handle_type = wintypes.UINT


def bind(library, name, arguments, result=wintypes.UINT):
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = result
    return function


open_database = bind(msi, "MsiOpenDatabaseW", [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(handle_type)])
open_view = bind(msi, "MsiDatabaseOpenViewW", [handle_type, wintypes.LPCWSTR, ctypes.POINTER(handle_type)])
execute_view = bind(msi, "MsiViewExecute", [handle_type, handle_type])
fetch_record = bind(msi, "MsiViewFetch", [handle_type, ctypes.POINTER(handle_type)])
field_count = bind(msi, "MsiRecordGetFieldCount", [handle_type])
get_string = bind(msi, "MsiRecordGetStringW", [handle_type, wintypes.UINT, wintypes.LPWSTR,
                                           ctypes.POINTER(wintypes.DWORD)])
close_handle = bind(msi, "MsiCloseHandle", [handle_type])
open_package = bind(msi, "MsiOpenPackageExW", [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(handle_type)])
set_property = bind(msi, "MsiSetPropertyW", [handle_type, wintypes.LPCWSTR, wintypes.LPCWSTR])
do_action = bind(msi, "MsiDoActionW", [handle_type, wintypes.LPCWSTR])
get_feature_state = bind(msi, "MsiGetFeatureStateW", [handle_type, wintypes.LPCWSTR,
                                                  ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)])
get_component_state = bind(msi, "MsiGetComponentStateW", [handle_type, wintypes.LPCWSTR,
                                                      ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)])
set_internal_ui = bind(msi, "MsiSetInternalUI", [wintypes.UINT, ctypes.c_void_p])
evaluate_condition = bind(msi, "MsiEvaluateConditionW", [handle_type, wintypes.LPCWSTR], ctypes.c_int)
load_library = bind(kernel, "LoadLibraryExW", [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD], wintypes.HMODULE)
free_library = bind(kernel, "FreeLibrary", [wintypes.HMODULE], wintypes.BOOL)
find_resource = bind(kernel, "FindResourceW", [wintypes.HMODULE, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p)
resource_size = bind(kernel, "SizeofResource", [wintypes.HMODULE, ctypes.c_void_p], wintypes.DWORD)
load_resource = bind(kernel, "LoadResource", [wintypes.HMODULE, ctypes.c_void_p], ctypes.c_void_p)
lock_resource = bind(kernel, "LockResource", [ctypes.c_void_p], ctypes.c_void_p)
resource_callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HMODULE, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_ssize_t)
enum_resources = bind(kernel, "EnumResourceNamesW", [wintypes.HMODULE, ctypes.c_void_p,
                                                   resource_callback, ctypes.c_ssize_t], wintypes.BOOL)


def check(code, operation):
    if code:
        raise OSError(code, f"{operation}: {ctypes.FormatError(code).strip()}")


@contextlib.contextmanager
def opened(function, *arguments):
    handle = handle_type()
    check(function(*arguments, ctypes.byref(handle)), function.__name__)
    try:
        yield handle
    finally:
        close_handle(handle)


def rows(database, statement):
    with opened(open_view, database, statement) as view:
        check(execute_view(view, 0), "Execute MSI query")
        while True:
            record = handle_type()
            code = fetch_record(view, ctypes.byref(record))
            if code == 259:
                return
            check(code, "Read MSI row")
            try:
                values = []
                for index in range(1, field_count(record) + 1):
                    size = wintypes.DWORD(4096)
                    buffer = ctypes.create_unicode_buffer(size.value)
                    check(get_string(record, index, buffer, ctypes.byref(size)), "Read MSI field")
                    values.append(buffer.value)
                yield values
            finally:
                close_handle(record)


def assert_true(value, message):
    if not value:
        raise AssertionError(message)


def icon_frames(executable):
    module = load_library(str(executable), None, 0x60)
    if not module:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        groups = []

        @resource_callback
        def collect(image, kind, name, parameter):
            resource = find_resource(image, name, kind)
            pointer = lock_resource(load_resource(image, resource))
            groups.append(ctypes.string_at(pointer, resource_size(image, resource)))
            return True

        if not enum_resources(module, 14, collect, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        assert_true(len(groups) == 1, f"Expected one application icon in {executable.name}")
        group = groups[0]
        count = struct.unpack_from("<H", group, 4)[0]
        images = {}
        for index in range(count):
            width, height, _, _, _, _, length, identifier = struct.unpack_from("<BBBBHHIH", group, 6 + 14 * index)
            assert_true(width == height, "The application icon is not square")
            resource = find_resource(module, identifier, 3)
            pointer = lock_resource(load_resource(module, resource))
            images[width or 256] = hashlib.sha256(ctypes.string_at(pointer, length)).hexdigest()
        return images
    finally:
        free_library(module)


def verify(package, payload, output):
    output.mkdir(parents=True, exist_ok=True)
    report = {"package": str(package), "feature_combinations": [], "icons": {}}
    with opened(open_database, str(package), None) as database:
        features = {row[0] for row in rows(database, "SELECT `Feature` FROM `Feature`")}
        assert_true(features == {"Collector", "Viewer", "Relay", "Publisher"},
                    "The installer must expose capture, viewer, and optional output services")
        components = list(rows(database, "SELECT `Feature_`, `Component_` FROM `FeatureComponents`"))
        assert_true({"EndpointAdapter", "EndpointSchema", "LoopbackLibrary", "LoopbackDriver", "LoopbackLicense"}
                    <= {component for feature, component in components if feature == "Collector"},
                    "The Collector feature omits an endpoint adapter or loopback dependency")
        upgrade_code = list(rows(database, "SELECT `Value` FROM `Property` WHERE `Property`='UpgradeCode'"))[0][0]
        guard = list(rows(database, "SELECT `Condition` FROM `InstallExecuteSequence` "
                                   "WHERE `Action`='CheckCollectorService'"))[0][0]
        services = list(rows(database, "SELECT `Name`, `StartType`, `StartName`, `Arguments`, `Component_` "
                                        "FROM `ServiceInstall`"))
        assert_true(len(services) == 3 and {row[0] for row in services} ==
                    {"Cipherazzi", "CipherazziRelay", "CipherazziPublisher"}, "Managed services are missing")
        for name, start, account, arguments, component in services:
            assert_true(start == "2" and account == "LocalSystem" and arguments.startswith("--service"),
                        f"Incorrect service setup: {name}")
        assert_true(any(row[0] == "Cipherazzi" and "[COLLECTOROPTIONS]" in row[3] for row in services),
                    "Collector options cannot be supplied during deployment")
        controls = list(rows(database, "SELECT `Name`, `Event`, `Wait`, `Component_` FROM `ServiceControl`"))
        assert_true(len(controls) == 3 and all(int(row[1]) & 163 == 163 and row[2] == "1" for row in controls),
                    "Service start, stop, removal, or shutdown waiting is missing")
        permissions = list(rows(database, "SELECT `SDDLText` FROM `MsiLockPermissionsEx`"))
        assert_true(len(permissions) == 1 and "(A;OICI;GRGX;;;BU)" in permissions[0][0]
                    and "(A;OICI;FA;;;BU)" not in permissions[0][0], "Journal access must be read-only for users")
        shortcuts = list(rows(database, "SELECT `Target`, `Icon_` FROM `Shortcut`"))
        assert_true(shortcuts == [["Viewer", "Cipherazzi.ico"]], "The Viewer shortcut must belong to its feature")
        files = list(rows(database, "SELECT `FileName`, `FileSize`, `Component_` FROM `File`"))
        directories = {identifier: (parent, name) for identifier, parent, name in
                       rows(database, "SELECT `Directory`, `Directory_Parent`, `DefaultDir` FROM `Directory`")}
        component_directories = dict(rows(database, "SELECT `Component`, `Directory_` FROM `Component`"))
        locations = {}

        # Verify payload files at their installed relative paths, including capture backend dependencies.
        for name, length, component in files:
            directory, segments, visited = component_directories[component], [], set()
            while directory != "INSTALLFOLDER":
                assert_true(directory in directories and directory not in visited,
                            "A payload directory is outside the application folder")
                visited.add(directory)
                parent, folder = directories[directory]
                folder = folder.split(":")[0].split("|")[-1]
                if folder != ".":
                    segments.insert(0, folder)
                directory = parent
            relative = Path(*segments) / name.split("|")[-1]
            path = payload / relative
            assert_true(path.resolve().is_relative_to(payload), "A payload path escapes the application folder")
            assert_true(path.stat().st_size == int(length), f"Packaged file size differs: {path.name}")
            locations[path.name] = relative.as_posix()
        assert_true(locations.get("WinDivert.dll") == "CipherazziLoopback/WinDivert.dll" and
                    locations.get("WinDivert64.sys") == "CipherazziLoopback/WinDivert64.sys",
                    "The loopback backend is outside the collector's expected directory")
        assert_true(not any(name.split("|")[-1].endswith(".db") for name, _, _ in files),
                    "Capture journals must not be managed installer payload")
        report["payload_files"] = list(locations.values())

    previous_ui = set_internal_ui(2, None)
    try:
        choices = [set(combination) for count in range(1, 5)
                   for combination in itertools.combinations(sorted(features), count)]
        for chosen in choices:
            with opened(open_package, str(package), 1) as session:
                check(set_property(session, "ADDLOCAL", ",".join(sorted(chosen))), "Select installer features")
                check(set_property(session, "INSTALLFOLDER", str(output / "cost") + "\\"), "Set target directory")
                for action in ["FindRelatedProducts", "AppSearch", "LaunchConditions", "CostInitialize",
                               "FileCost", "CostFinalize"]:
                    check(do_action(session, action), action)
                states = {}
                installed, requested = ctypes.c_int(), ctypes.c_int()
                for feature in features:
                    check(get_feature_state(session, feature, ctypes.byref(installed), ctypes.byref(requested)),
                          "Read feature state")
                    states[feature] = "install" if requested.value == 3 else "excluded"
                    assert_true(requested.value == 3 if feature in chosen else requested.value in {-1, 0, 2},
                                f"Wrong action for {feature} when selecting {sorted(chosen)}: {requested.value}")
                selected_components = {component for feature, component in components if feature in chosen}
                for component in {component for feature, component in components}:
                    check(get_component_state(session, component, ctypes.byref(installed), ctypes.byref(requested)),
                          "Read component state")
                    assert_true(requested.value == 3 if component in selected_components else requested.value in {-1, 0, 2},
                                f"Feature selection leaked into {component}: {requested.value}")
                report["feature_combinations"].append(states)
                check(set_property(session, "EXISTINGCOLLECTOR", "1"), "Simulate an existing service")
                assert_true(evaluate_condition(session, guard) == (1 if "Collector" in chosen else 0),
                            "An unmanaged service can be overwritten or incorrectly blocks Viewer installation")
                check(set_property(session, "COLLECTORINSTALLER", upgrade_code), "Simulate installer ownership")
                assert_true(evaluate_condition(session, guard) == 0, "An installer-owned service blocks maintenance")
    finally:
        set_internal_ui(previous_ui, None)

    expected = None
    for name in ["Cipherazzi.Collector.exe", "Cipherazzi.Viewer.exe", "Cipherazzi.Relay.exe"]:
        images = icon_frames(payload / name)
        assert_true(set(images) == {16, 20, 24, 32, 40, 48, 64, 96, 128, 256}, f"Missing icon sizes in {name}")
        if expected is None:
            expected = images
        assert_true(images == expected, f"Inconsistent application icon in {name}")
        report["icons"][name] = sorted(images)
    report["result"] = "passed"
    (output / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Verify MSI feature selection, service lifecycle, and executable icons.")
    parser.add_argument("package", type=Path)
    parser.add_argument("payload", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    verify(arguments.package.resolve(), arguments.payload.resolve(), arguments.output.resolve())
