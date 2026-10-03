cmake_minimum_required(VERSION 3.28)
set(CIPHERAZZI_VERSION "1.0.0" CACHE STRING "Cipherazzi product version")
project(Cipherazzi VERSION ${CIPHERAZZI_VERSION} LANGUAGES C CXX RC)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Cipherazzi requires Windows and the MSVC toolchain.")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
option(CIPHERAZZI_ASAN "Enable AddressSanitizer for native verification" OFF)
if(CIPHERAZZI_ASAN)
    add_compile_options(/fsanitize=address /Zi)
    add_link_options(/DEBUG)
endif()

include(FetchContent)
FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530400.zip
    URL_HASH SHA3_256=628a44cfe82c66aed1ccbbe85a562d2e33ebe64b3288981ed76285612227934e
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(sqlite)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(json)
FetchContent_Declare(windivert
    URL https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
    URL_HASH SHA256=63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(windivert)
add_library(sqlite STATIC "${sqlite_SOURCE_DIR}/sqlite3.c")
target_include_directories(sqlite PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(sqlite PRIVATE SQLITE_THREADSAFE=1 SQLITE_DQS=0 SQLITE_OMIT_LOAD_EXTENSION)

add_library(cipherazzi_core STATIC
    collector/Configuration.cpp
    collector/Model.cpp
    collector/Crypto.cpp
    collector/Telemetry.cpp
    collector/Tls.cpp
    collector/Network.cpp
    collector/NetworkEngine.cpp
    collector/Protocols.cpp
    collector/Framing.cpp
    collector/Auth.cpp
    collector/Rdma.cpp
    collector/Vpn.cpp
    collector/Engine.cpp
    collector/Quic.cpp
    collector/Storage.cpp
    collector/Retention.cpp
    collector/Processes.cpp
    collector/Loopback.cpp
    collector/Capture.cpp)
target_include_directories(cipherazzi_core PUBLIC collector)
target_include_directories(cipherazzi_core PRIVATE "${windivert_SOURCE_DIR}/include")
target_compile_definitions(cipherazzi_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(cipherazzi_core PRIVATE /W4 /permissive- /utf-8 /EHsc)
target_link_libraries(cipherazzi_core PUBLIC sqlite nlohmann_json::nlohmann_json
    ws2_32 iphlpapi advapi32 secur32 tdh crypt32 wevtapi bcrypt)

configure_file(collector/Resources.rc.in "${CMAKE_CURRENT_BINARY_DIR}/Collector.rc" @ONLY)
set(CIPHERAZZI_WINDOWS_KITS "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots;KitsRoot10]")
find_program(CIPHERAZZI_MC mc.exe
    HINTS "${CIPHERAZZI_WINDOWS_KITS}/bin/${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}/x64"
    REQUIRED)
set(CIPHERAZZI_EVENT_RESOURCES "${CMAKE_CURRENT_BINARY_DIR}/event-resources")
file(MAKE_DIRECTORY "${CIPHERAZZI_EVENT_RESOURCES}")
add_custom_command(
    OUTPUT "${CIPHERAZZI_EVENT_RESOURCES}/EventMessages.rc"
        "${CIPHERAZZI_EVENT_RESOURCES}/EventMessages.h" "${CIPHERAZZI_EVENT_RESOURCES}/EventMessages.bin"
    COMMAND "${CIPHERAZZI_MC}" -U -h "${CIPHERAZZI_EVENT_RESOURCES}" -r "${CIPHERAZZI_EVENT_RESOURCES}"
        "${PROJECT_SOURCE_DIR}/collector/EventMessages.mc"
    DEPENDS collector/EventMessages.mc VERBATIM)
add_executable(Cipherazzi.Collector collector/Main.cpp collector/Service.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/Collector.rc" "${CIPHERAZZI_EVENT_RESOURCES}/EventMessages.rc")
target_include_directories(Cipherazzi.Collector PRIVATE "${CIPHERAZZI_EVENT_RESOURCES}")
target_link_libraries(Cipherazzi.Collector PRIVATE cipherazzi_core shell32 ole32)
target_compile_options(Cipherazzi.Collector PRIVATE /W4 /permissive- /utf-8 /EHsc)
add_custom_command(TARGET Cipherazzi.Collector POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:Cipherazzi.Collector>/CipherazziLoopback"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${windivert_SOURCE_DIR}/x64/WinDivert.dll"
        "${windivert_SOURCE_DIR}/x64/WinDivert64.sys" "${windivert_SOURCE_DIR}/LICENSE"
        "$<TARGET_FILE_DIR:Cipherazzi.Collector>/CipherazziLoopback" VERBATIM)

option(CIPHERAZZI_ENDPOINT_ADAPTER "Build the public endpoint adapter" ON)
if(CIPHERAZZI_ENDPOINT_ADAPTER)
    FetchContent_Declare(frida_core
        URL https://github.com/frida/frida/releases/download/17.23.1/frida-core-devkit-17.23.1-windows-x86_64.tar.xz
        URL_HASH SHA256=a3d5e6095d4f304d9b36d5e4e356968e1bbbd5938a0db983cfc5f36fb2481b02
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(frida_core)
    configure_file(adapters/Resources.rc.in "${CMAKE_CURRENT_BINARY_DIR}/EndpointAdapter.rc" @ONLY)
    add_executable(Cipherazzi.EndpointAdapter adapters/EndpointAdapter.cpp
        "${CMAKE_CURRENT_BINARY_DIR}/EndpointAdapter.rc")
    set_property(TARGET Cipherazzi.EndpointAdapter PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)
    target_include_directories(Cipherazzi.EndpointAdapter PRIVATE "${frida_core_SOURCE_DIR}")
    target_compile_definitions(Cipherazzi.EndpointAdapter PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_compile_options(Cipherazzi.EndpointAdapter PRIVATE /W4 /permissive- /utf-8 /EHsc)
    target_link_libraries(Cipherazzi.EndpointAdapter PRIVATE nlohmann_json::nlohmann_json
        "${frida_core_SOURCE_DIR}/frida-core.lib" setupapi ws2_32 crypt32 iphlpapi winhttp)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(Cipherazzi.Tests tests/Tests.cpp tests/Protocols.cpp tests/Vpn.cpp tests/Network.cpp tests/Rdma.cpp
        tests/Retention.cpp tests/EndpointIntegration.cpp)
    target_link_libraries(Cipherazzi.Tests PRIVATE cipherazzi_core)
    target_compile_definitions(Cipherazzi.Tests PRIVATE CIPHERAZZI_FIXTURE_DIRECTORY="${CMAKE_SOURCE_DIR}/tests/fixtures")
    target_compile_options(Cipherazzi.Tests PRIVATE /W4 /permissive- /utf-8 /EHsc)
    add_test(NAME collector COMMAND Cipherazzi.Tests)
endif()
