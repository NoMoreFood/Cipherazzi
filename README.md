# Cipherazzi

Cipherazzi observes network cryptography on Windows workstations and servers. It records visible protocol negotiation, local process ownership, public certificates, and optional endpoint telemetry in a local SQLite journal. The desktop viewer provides connection investigation, analytics, certificate inventory, post-quantum readiness, and scoped policy evaluation. An optional relay publishes metadata to SQL Server or PostgreSQL for fleet analysis. An optional event publisher sends metadata to syslog and Windows Event Log.

Evidence is explicit: a server hello establishes an observed selection; endpoint telemetry can report handshake completion and peer verification. Missing or encrypted evidence remains unknown. Read [capture coverage and limitations](docs/Coverage.md) before interpreting results or planning an enterprise rollout.

## Components

| Component | Purpose |
| --- | --- |
| `Cipherazzi.Collector.exe` | Native collector using Windows Packet Monitor and packaged loopback capture, with bounded protocol inspection and automatic local retention. Runs interactively or as the `Cipherazzi` Windows service. |
| `Cipherazzi.Viewer.exe` | Desktop investigation of a local journal or remote database. Local journals are opened read-only. |
| `Cipherazzi.Relay.exe` | Resumable upload of committed journal metadata to SQL Server or PostgreSQL, with durable local acknowledgements. |
| `Cipherazzi.Publisher.exe` | Optional TLS syslog and Windows Application log publishing with independent destination cursors and bounded metadata. |
| [Watch-Java.ps1](Watch-Java.ps1) | Optional Java Flight Recorder watcher for a selected JVM. |

Live collection uses Windows Packet Monitor streaming for network traffic and a packaged, signed WinDivert driver for same-host (loopback) TCP and UDP, and requires elevation. Use `--no-loopback` to collect without the driver. See [capture coverage and limitations](docs/Coverage.md#process-ownership-and-capture-sources).

## Quick start

From the repository root, [build and publish](#build) the applications:

```powershell
.\Build.ps1 -Publish
```

In an elevated PowerShell console, create a journal directory and start collecting:

```powershell
New-Item -ItemType Directory -Path .\captures -Force | Out-Null
.\dist\Cipherazzi.Collector.exe --db .\captures\capture.db
```

In another console at the repository root, open the journal:

```powershell
.\dist\Cipherazzi.Viewer.exe .\captures\capture.db
```

Use **Live** to follow committed changes and **Capture health** to inspect losses, inspection limits, and retention status. Press Ctrl+C in the collector console to drain and stop collection. Opening or closing the viewer does not start or stop the collector.

The default collector limits are 32,768 tracked flows, a 128 MiB protocol inspection budget, 30-day age retention, and a 512 MiB live journal page target. Active data and pending registered relay or event publishing uploads are protected, so physical storage can exceed the target. See [deployment and retention](docs/Deployment.md).

For managed installation, `Build.ps1 -Installer` produces `dist\Cipherazzi-win-x64.msi`. The MSI offers Collector and Viewer features and starts the collector service when that feature is installed.

## Build

Build on x64 Windows with:

- Visual Studio 2026 with the Desktop development with C++ workload and Windows SDK. The build script selects the `Visual Studio 18 2026` CMake generator.
- CMake with support for the `Visual Studio 18 2026` generator, available on PATH or through Visual Studio. The project declares a minimum of 3.28; the selected generator must also be supported by the installed CMake.
- The .NET 10 SDK for the viewer, relay, publisher, and managed checks.
- Access to the dependency download and NuGet feeds, or an already populated build/package cache.

```powershell
.\Build.ps1
.\Build.ps1 -Configuration Debug
.\Build.ps1 -Publish
.\Build.ps1 -Installer
```

`Build.ps1` builds the native collector, runs its CTest checks, and builds the viewer, relay, and publisher. `-Publish` also creates self-contained x64 applications in `dist`; `-Installer` publishes and builds the MSI. Published managed applications include their runtime. Framework-dependent build output requires the corresponding .NET runtime.

Release build output is under `build\bin\Release`, `viewer\bin\Release\net10.0-windows`, `relay\bin\Release\net10.0`, and `publisher\bin\Release\net10.0-windows`. The build script accepts `-ProductVersion` for package versioning.

## Documentation

- [Deployment and operations](docs/Deployment.md): installation, collector options, retention, relay setup, resource planning, and security.
- [Using the viewer](docs/Viewer.md): filtering, investigation, native certificate viewing, readiness, policies, and settings.
- [Capture coverage and limitations](docs/Coverage.md): observable protocol fields and evidence boundaries.
- [Endpoint telemetry](docs/EndpointTelemetry.md): Schannel/CAPI2, Java, and application report contracts.
- [Event publishing](docs/Publishing.md): TLS syslog, Windows Event Log, event selection, delivery, and retention.
- [Verification and performance checks](tests/README.md): native, integration, database, UI, and VM checks and their prerequisites.

## Source layout

| Directory | Contents |
| --- | --- |
| [collector](collector/) | C++ capture, protocol parsers, process attribution, storage, retention, and service support. |
| [data](data/) | Shared database access, replication, evidence interpretation, and policy evaluation. |
| [viewer](viewer/) | Windows desktop application and default configuration. |
| [relay](relay/) | Remote replication command-line application. |
| [publisher](publisher/) | Syslog and Windows Event Log publisher and event schema. |
| [installer](installer/) | WiX MSI project. |
| [tests](tests/) | Native checks, client programs, integration harnesses, and lab automation. |

The viewer's **Help** button and F1 open the prospective [Cipherazzi GitHub home](https://github.com/NoMoreFood/Cipherazzi).
