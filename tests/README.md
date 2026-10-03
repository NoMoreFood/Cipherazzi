# Verification and performance checks

Run commands from the repository root unless a different directory is specified. Use isolated output directories and disposable database/VM targets. The test tools produce journals, logs, JSON results, and screenshots under `.work` or the supplied output path; inspect both exit status and artifacts.

## Build and native checks

`Build.ps1` builds the collector, runs CTest, and builds the viewer, relay, and publisher:

```powershell
.\Build.ps1
```

To repeat native checks without rebuilding, with CTest on PATH:

```powershell
ctest --test-dir .\build -C Release --output-on-failure
```

Native checks cover parsing, reassembly, malformed and bounded inputs, network protocols, retention, and storage behavior. To build a separate AddressSanitizer configuration with CMake and the MSVC toolchain available:

```powershell
cmake -S . -B .\build\asan -G 'Visual Studio 18 2026' -A x64 -DBUILD_TESTING=ON -DCIPHERAZZI_ASAN=ON
cmake --build .\build\asan --config Release --parallel
ctest --test-dir .\build\asan -C Release --output-on-failure
```

The repository's [build prerequisites](../README.md#build) also apply to these checks.

## Actual TLS exchanges and replay

[Integration.py](Integration.py) requires Python, an OpenSSL executable, a JDK `java.exe` capable of source-file execution, the .NET SDK, and a built collector/viewer. Specify installed executable paths:

```powershell
python .\tests\Integration.py --java 'C:\Java\jdk\bin\java.exe' --openssl 'C:\OpenSSL\bin\openssl.exe'
```

The harness makes real Java, Schannel, and OpenSSL-based TLS 1.2/1.3 exchanges, records their bytes in a classic PCAP, replays them through the collector, checks database integrity and visible negotiated fields, and performs viewer read/render smoke checks. It writes `.work\latest-integration.json`, including the generated journal and screenshot paths.

This verifies actual negotiation and the replay parser. Live Packet Monitor coverage is checked separately using traffic crossing the lab VM's network interface. The integration fixture contains six connections and is suitable for read/render smoke checks.

## Viewer and UI checks

A built viewer can read a journal without an interactive investigation session:

```powershell
.\viewer\bin\Release\net10.0-windows\Cipherazzi.Viewer.exe --verify .\capture.db
.\viewer\bin\Release\net10.0-windows\Cipherazzi.Viewer.exe --verify-ui .\capture.db .\viewer.png
```

`--verify` checks readable data and health. `--verify-ui` renders the viewer to the supplied image and exits. For reliable exit-status/output collection from the GUI executable in PowerShell, use `Start-Process -Wait -PassThru` and output redirection in automation.

The [UiTests project](UiTests/Cipherazzi.UiTests.csproj) runs observable desktop workflows and rendering checks. It requires an interactive Windows desktop. Set `$uiFixture` to a test journal with at least 250 rows visible under the default filter and observed certificate data for the general suite:

```powershell
$uiFixture = 'C:\CipherazziLab\capture.db'
dotnet run --project .\tests\UiTests\Cipherazzi.UiTests.csproj -c Release -- $uiFixture .\.work\ui-checks
dotnet run --project .\tests\UiTests\Cipherazzi.UiTests.csproj -c Release -- --layout-audit $uiFixture .\.work\layout-checks
dotnet run --project .\tests\UiTests\Cipherazzi.UiTests.csproj -c Release -- --scroll-audit $uiFixture .\.work\scroll-checks
```

Use `--protocol-ui <db> <output>` with a mixed SSH/raw/WireGuard/IKEv2/OpenVPN fixture. Adding `--network` selects the expected DTLS 1.0/1.2 and TLS 1.3/QUIC path scenarios. Adding `--negotiation` expects the journal produced by replaying the capture that [NegotiationFixture.py](NegotiationFixture.py) writes: Kerberos change-password exchanges, a Kerberos reply beyond 64 KiB, the TDS encryption outcomes, and an SMB1 dialect selection, with the findings they raise. See [ProtocolUi.cs](UiTests/ProtocolUi.cs) for the required evidence; a standalone live DTLS journal needs the additional scenarios before this UI check can run. Migration and performance UI modes require the migration evidence scenarios expected by their harness. `--dpi-unaware` selects the 100% DPI test mode; also run with the normal DPI mode at the target desktop scale. Inspect screenshots for clipping, alignment, theme contrast, and native certificate actions.

The general SQLite suite verifies negotiation-history truncation updates and preserves the selected negotiation property during refresh. It also checks that unchanged inspector snapshots reuse their property descriptors. Protocol uses Alt+P and Partial exchanges uses Alt+X; the layout audit checks for duplicate access keys. The 2026-10-06 local rerun passed the general suite and all 78 layout frames at the desktop's configured DPI. Remote providers, certificate actions, and protocol rendering need their own relevant verification evidence.

## Database and relay checks

The [DatabaseLab project](DatabaseLab/DatabaseLab.csproj) exercises provider behavior, interrupted operations, policy/readiness evidence, and relay acknowledgement safety. Some modes expect specifically prepared data; inspect the selected harness's arguments and fixture before execution.

| Mode | Focus |
| --- | --- |
| Default replication run | SQL Server/PostgreSQL upload and metadata/certificate consistency. |
| `--retention` | Upload acknowledgement, failed remote commit, multiple destinations, local pruning, and preserved remote history. |
| `--sqlite-stress` | Cancellation of a long native SQLite aggregate. |
| `--stress`, `--advanced`, `--connectivity` | Connectivity, interrupted requests, and packaged application workflows. |
| `--pqc`, `--migration`, `--migration-remote` | Post-quantum classification, policies, baselines, and provider parity with their expected fixtures. |
| `--data-stress` | Adversarial data and bounded processing scenarios. |

The retention scenario needs a seed journal plus disposable SQL Server and PostgreSQL servers with connection strings in `CIPHERAZZI_SQLSERVER` and `CIPHERAZZI_POSTGRESQL`. Its accounts must be able to create and drop temporary databases. It also uses the native Release collector to execute cleanup. With those prerequisites prepared:

```powershell
$seedJournal = 'C:\CipherazziLab\capture.db'
dotnet run --project .\tests\DatabaseLab\DatabaseLab.csproj -c Release -- --retention $seedJournal .\.work\retention-checks
dotnet run --project .\tests\DatabaseLab\DatabaseLab.csproj -c Release -- --sqlite-stress $seedJournal .\.work\sqlite-checks
```

Remote checks can mutate databases and create artifacts containing connection strings. Restrict lab output access and use test credentials. Keep these checks separate from production replication and retention.

## Event publishing checks

The [Publishing project](Publishing/Publishing.csproj) runs actual publisher processes against collector replay output and local TCP/TLS receivers. It verifies server trust and hostname rejection, private CA and mutual TLS, Unicode framing and bounded metadata, event filters, shared-revision pagination, interrupted delivery, durable cursors, duplicate-instance exclusion, health throttling and warnings, and retention protection. Each run requires a new output directory:

```powershell
dotnet run --project .\tests\Publishing\Publishing.csproj -c Release -- `
    .\dist\Cipherazzi.Publisher.exe .\dist\Cipherazzi.Collector.exe .\.work\publishing-checks
```

Appending `--windows-events` requires an elevated test process and also verifies source registration, independent Windows delivery while syslog fails, event IDs, and native message rendering. The harness registers a uniquely named temporary Application source and removes its registry key when finished. Test events remain in the Application log. It adds a temporary client certificate to the running account's personal certificate store for mutual TLS and removes it in cleanup; it does not add a trust root.

`results.json` records each check and process CPU, elapsed time, and sampled peak working set. The idle scenario runs for twelve seconds at the default poll interval; `cpu_after_startup_ms` and `elapsed_after_startup_ms` exclude the first two seconds. Other timed scenarios contain active journal updates, so their corresponding fields are not idle measurements. The first run of a self-contained executable can include runtime/native-library extraction. Record that separately when interpreting startup.

To test packaged executables in the prepared VM, first publish the test harness:

```powershell
dotnet publish .\tests\Publishing\Publishing.csproj -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
    -o .\.work\publishing-check\test-tool
.\tests\lab\Invoke-PublishingLab.ps1
```

Run the lab script from an elevated PowerShell host after `Build.ps1 -Publish`. It copies the published collector, publisher, and test tool into a dedicated guest directory, runs the suite with Windows events, copies output back, and restores a VM it started to the off state. The collector only replays PCAP fixtures during these checks.

## Hyper-V lab

The [lab scripts](lab/) require an elevated PowerShell host with Hyper-V, a Default Switch, PowerShell Direct access, and a dedicated Windows test VM. [New-Lab.ps1](lab/New-Lab.ps1) accepts a Windows Enterprise ISO containing `install.wim` and creates a VM with a `Cipherazzi-Lab-*` name:

```powershell
.\tests\lab\New-Lab.ps1 -IsoPath 'C:\Images\WindowsEnterprise.iso' -Name Cipherazzi-Lab-Tests
```

Lab state is stored in `.work\hyperv\lab.json`; its credential file is protected for the creating Windows account. Prepare published applications with `Build.ps1 -Publish`, run the TLS integration fixture, and stage the runtime payloads expected by each runner under `.work\lab-payload`. The basic runner expects `java.zip`, `python.zip`, and `schannel\SchannelClient.exe`; OpenSSL suites need an `openssl` directory containing `openssl.exe` and its dependencies. Archive layouts must match the executable paths used in the scripts.

The runners assume a prepared lab. Some use host-specific Python paths and Default Switch address assumptions; inspect and adapt those to the lab host before running. Runners can start/reboot the VM, install/remove a service, and temporarily change firewall rules, routes, or offload settings. Use the dedicated VM and preserve output for cleanup verification.

| Runner | Focus |
| --- | --- |
| [Invoke-Lab.ps1](lab/Invoke-Lab.ps1) | Basic live TLS, process ownership, viewer, and optional `-Telemetry` sources. |
| [Invoke-ServiceLab.ps1](lab/Invoke-ServiceLab.ps1) | Service lifecycle and restart scenarios. |
| [Invoke-ProtocolLab.ps1](lab/Invoke-ProtocolLab.ps1) | SSH and raw traffic, optionally with `-ClassifyRaw`. |
| [Invoke-PqcLab.ps1](lab/Invoke-PqcLab.ps1) | PQC or advanced authentication/certificate/QUIC suites selected by `-Suite`. |
| [Invoke-NetworkLab.ps1](lab/Invoke-NetworkLab.ps1) | Live DTLS 1.0/1.2 and IPv4 fragments. |
| [Invoke-PublishingLab.ps1](lab/Invoke-PublishingLab.ps1) | Packaged syslog and Windows Event Log delivery, failure recovery, retention, and process resource measurements. |
| [Invoke-LiveCaptureLab.ps1](lab/Invoke-LiveCaptureLab.ps1) | Handshake latency and live collection under a chosen bulk rate. |
| [Invoke-CaptureCapacityLab.ps1](lab/Invoke-CaptureCapacityLab.ps1) | Download, raw classification, duplex, and custom capacity profiles. |

Use [Get-LabState.ps1](lab/Get-LabState.ps1) with `-Name Cipherazzi-Lab-Tests` (or the chosen VM name) to inspect the lab and [Stop-Lab.ps1](lab/Stop-Lab.ps1) to shut it down when finished. Check each runner's recorded results, collector health, endpoint results, and cleanup outcome.

## Performance

The [PerformanceAudit project](PerformanceAudit/PerformanceAudit.csproj) measures full database workflows, including first-call and repeated elapsed time, CPU, allocation, and working set:

```powershell
dotnet run --project .\tests\PerformanceAudit\PerformanceAudit.csproj -c Release -- .\capture.db .\.work\performance.json --features
dotnet run --project .\tests\PerformanceAudit\PerformanceAudit.csproj -c Release -- --query-costs .\capture.db .\.work\query-costs.json
```

`--features` includes readiness, policy, and certificate inventory reads. The first-call measurement is not a full cold application startup measurement: measure process launch and the first usable view separately. Remote reads accept `sqlserver` or `postgresql` as the first argument and use `CIPHERAZZI_CONNECTION`.

[NativeAudit.ps1](PerformanceAudit/NativeAudit.ps1) compares collector replay against local and workspace storage with the same input. The live and capacity VM runners measure interface capture under concurrent handshake and bulk workloads. Capacity profiles use `label`, `rate` in MiB/s, `direction` (`download`, `upload`, or `both`), `handshakes` per second, `raw`, and `baseline` fields; supply a JSON profile array through `-Profiles` to represent the deployment workload.

Measure idle/startup, ordinary workstation activity, busy server/storage activity, and sustained bursts. Compare collection enabled and disabled on the same environment. Record OS image, CPU, memory, interface/offload state, storage, throughput, handshake rate, collector options, viewer scope, and capture/queue losses. CPU percentages should specify whether they are relative to one logical core or the whole machine.

Separate realistic enterprise workloads from stress cases beyond the supported profile. A low CPU result with dropped packets is not full coverage, and replay speed alone is not a live capture capacity guarantee. See [deployment resource planning](../docs/Deployment.md#resource-planning-and-operations) and [coverage limits](../docs/Coverage.md#capacity-and-confidence).

## Detection matrix interpretation

The separate `Cipherazzi-Test` repository contains the reference traffic and detection matrix scripts, including `Run-All-Tests.ps1`, `Verify-Detection.py`, and `Run-Reference-Matrix.py`. When using it alongside this checkout, point verification at the collector journal produced by that run. Its generated `CIPHERAZZI_DETECTION_REPORT.md` files are evidence for their original runs and should be preserved.

Count detected probes and verified fields separately. A test can create a successful endpoint exchange while passive capture still lacks encrypted authentication, loopback visibility, or endpoint completion evidence. Classify unavailable fields as coverage limits rather than silently passing them. Keep fixture-only DTLS 1.3/IPv6 checks distinct from live DTLS 1.0/1.2/IPv4 validation, and record failures and capture losses alongside passing observations.
