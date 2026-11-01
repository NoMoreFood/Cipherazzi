# Cipherazzi

Cipherazzi observes network cryptography on Windows workstations and servers. It records visible protocol negotiation, local process ownership, public certificates, and optional endpoint telemetry in a local SQLite journal. The desktop viewer provides connection investigation, analytics, certificate inventory, post-quantum readiness, and scoped policy evaluation. An optional relay publishes metadata to SQL Server or PostgreSQL for fleet analysis. An optional event publisher sends metadata and policy assessments to syslog and Windows Event Log. Opt-in [HTTP Spy](docs/Deployment.md#http-spy) captures decoded web messages in a separate private store.

Evidence is explicit: a server hello establishes an observed selection; endpoint telemetry can report handshake completion and peer verification. Missing or encrypted evidence remains unknown. Read [capture coverage and limitations](docs/Coverage.md) before interpreting results or planning an enterprise rollout.

## Components

| Component | Purpose |
| --- | --- |
| `Cipherazzi.Collector.exe` | Native collector using Windows Packet Monitor and packaged loopback capture, with bounded protocol inspection and automatic local retention. Runs interactively or as the `Cipherazzi` Windows service. |
| `Cipherazzi.Viewer.exe` | Desktop investigation of a local journal or remote database. Local journals are opened read-only. |
| `Cipherazzi.Relay.exe` | Resumable upload of committed journal metadata to SQL Server or PostgreSQL, with durable local acknowledgements. |
| `Cipherazzi.Publisher.exe` | Optional TLS syslog and Windows Application log publishing with independent destination cursors and bounded metadata. |

Live collection uses Windows Packet Monitor streaming for network traffic and a packaged, signed WinDivert driver for same-host (loopback) TCP and UDP, and requires elevation. Use `--no-loopback` to collect without the driver. See [capture coverage and limitations](docs/Coverage.md#process-ownership-and-capture-sources).

## Quick start

From the repository root, [build and publish](#build) the applications:

```powershell
.\Build\Build.ps1 -Publish
```

In an elevated PowerShell console, create a journal directory and start collecting:

```powershell
New-Item -ItemType Directory -Path .\Build\Temp\Captures -Force | Out-Null
.\Build\Output\Cipherazzi.Collector.exe --db .\Build\Temp\Captures\capture.db
```

In another console at the repository root, open the journal:

```powershell
.\Build\Output\Cipherazzi.Viewer.exe .\Build\Temp\Captures\capture.db
```

Use **Live** to follow committed changes and **Capture health** to inspect losses, inspection limits, and retention status. Press Ctrl+C in the collector console to drain and stop collection. Opening or closing the viewer does not start or stop the collector.

The default collector limits are 32,768 tracked flows, a 128 MiB protocol inspection budget, 30-day age retention, and a 512 MiB live journal page target. Active data and pending registered relay or event publishing uploads are protected, so physical storage can exceed the target. See [deployment and retention](docs/Deployment.md).

For managed installation, `Build\Build.ps1 -Installer` produces `Build\Output\Cipherazzi-win-x64.msi`. The MSI offers Collector and Viewer features, plus optional Relay and Publisher services configured through installer properties.

## Build

Build on x64 Windows with:

- Visual Studio 2026 with the Desktop development with C++ workload and Windows SDK. The build script locates MSBuild through Visual Studio Installer.
- PowerShell 7 and Python 3.12 or newer on PATH for build orchestration and offline verification fixtures.
- The .NET 10 SDK for the viewer, relay, publisher, and managed checks.
- Access to the dependency download and NuGet feeds, or an already populated build/package cache.

```powershell
.\Build\Build.ps1
.\Build\Build.ps1 -Configuration Debug
.\Build\Build.ps1 -Publish
.\Build\Build.ps1 -Installer
```

`Build\Build.ps1` builds the native and managed projects and runs offline native, data, and publishing checks. Add `-UiTests` to run desktop workflows and scaled layout checks on an interactive Windows desktop. `-SkipTests` skips verification. `-Publish` also creates self-contained x64 applications in `Build/Output`; `-Installer` publishes and builds the MSI. Published managed applications include their runtime. Framework-dependent build output requires the corresponding .NET runtime.

Release build output is under `Build\Temp\bin\Release`, `Build\Temp\managed\bin`. The build script accepts `-ProductVersion` for package versioning and `-Sign` when publishing or creating an installer.

## Documentation

- [Deployment and operations](docs/Deployment.md): installation, collector options, retention, relay setup, resource planning, and security.
- [Using the viewer](docs/Viewer.md): filtering, investigation, native certificate viewing, readiness, policies, and settings.
- [Capture coverage and limitations](docs/Coverage.md): observable protocol fields and evidence boundaries.
- [Endpoint telemetry](docs/EndpointTelemetry.md): Schannel/CAPI2, Java, and application report contracts.
- [Event publishing](docs/Publishing.md): TLS syslog, Windows Event Log, event selection, delivery, and retention.
- [Verification and performance checks](Test/README.md): native, integration, database, UI, and VM checks and their prerequisites.

## Source layout

| Directory | Contents |
| --- | --- |
| [collector](Source/Collector/) | C++ capture, protocol parsers, process attribution, storage, retention, and service support. |
| [data](Source/Data/) | Shared database access, replication, evidence interpretation, and policy evaluation. |
| [viewer](Source/Viewer/) | Windows desktop application and default configuration. |
| [relay](Source/Relay/) | Remote replication command-line application. |
| [publisher](Source/Publisher/) | Syslog and Windows Event Log publisher and event schema. |
| [shared](Source/Shared/) | Relay/publisher deployment support and native filesystem security helpers. |
| [deployment](Source/Deployment/) | Example collector, relay, and publisher configurations. |
| [assets](Source/Assets/) | Application and installer artwork. |
| [docs](docs/) | Deployment, operation, and evidence guides. |
| [installer](Source/Installer/) | WiX MSI project. |
| [tests](Test/) | Native checks, client programs, integration harnesses, and lab automation. |

The viewer's **Help** button and F1 open the [Cipherazzi GitHub home](https://github.com/NoMoreFood/Cipherazzi).
