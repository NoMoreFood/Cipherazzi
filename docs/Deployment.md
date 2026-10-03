# Deployment and operations

## Choose an installation

Use the MSI for enterprise installation with selected capture and output services. Capture options can be supplied through `COLLECTOROPTIONS`. A standalone collector service installation is also available. Both use the service name `Cipherazzi`; select one installation method for a machine.

The MSI requires x64 Windows with OS build 14393 or later (Windows 10 version 1607, Windows Server 2016). Live network capture also requires the Packet Monitor streaming APIs, including `PacketMonitorCreateRealtimeStream`, which Microsoft documents from Windows Server 2022. Where they are absent, the default capture selection continues with same-host traffic, process attribution, and endpoint sources, and the session's source says that network capture is unavailable; `--no-loopback` and `--source` still fail there. Verify live capture on every workstation and server OS image included in the rollout. The installer minimum alone does not establish capture availability on a particular build.

### MSI

Build the package with `Build.ps1 -Installer`, or obtain a built `Cipherazzi-win-x64.msi`. Run installation with administrative privileges. These examples run from the directory containing the MSI:

```powershell
msiexec.exe /i .\Cipherazzi-win-x64.msi /qn /norestart
msiexec.exe /i .\Cipherazzi-win-x64.msi ADDLOCAL=Collector /qn /norestart
msiexec.exe /i .\Cipherazzi-win-x64.msi ADDLOCAL=Viewer /qn /norestart
```

The first command installs Collector and Viewer. Collector includes the Java watcher, endpoint adapter, loopback capture package, and endpoint/publishing schemas. It also registers the `Cipherazzi` Windows Application event source. Viewer installs the desktop application, default configuration, and Start menu shortcut. The default application directory is `%ProgramFiles%\Cipherazzi`.

The Collector feature installs an automatically started LocalSystem service with default capture options. Its journal is `%ProgramData%\Cipherazzi\capture.db`; its log is `%ProgramData%\Cipherazzi\service.log`. Optional raw classification and endpoint sources require explicit collector options and are disabled in this default installation. Set `COLLECTOROPTIONS` to the desired continuous capture options. Relay and Publisher are optional features; provision their configuration files before selecting them:

```powershell
msiexec.exe /i .\Cipherazzi-win-x64.msi ADDLOCAL=Collector,Viewer `
    'COLLECTOROPTIONS=--replication-required --retention-mb 2048' /qn /norestart
msiexec.exe /i .\Cipherazzi-win-x64.msi ADDLOCAL=Collector,Viewer,Relay,Publisher `
    'RELAYCONFIG=C:\CipherazziConfig\relay.json' 'PUBLISHERCONFIG=C:\CipherazziConfig\publisher.json' /qn /norestart
```

Use the supplied `relay.example.json` and `publisher.example.json` as starting points. The services run as LocalSystem by default and require access to their configuration, journal, and account-protected credentials. The relay and publisher write operational logs under `%ProgramData%\Cipherazzi`. Service recovery also applies when a worker returns an error. Existing journal directories and their immediate children must be owned by Administrators or SYSTEM and must not be reparse points.

An existing standalone service must be removed using its collector's `--uninstall` before installing the MSI Collector feature. Use Windows installed-app management or the MSI to remove an MSI installation. Uninstalling preserves journals and logs.

### Standalone service

From an elevated console in a published application directory:

```powershell
.\Cipherazzi.Collector.exe --install --replication-required
sc.exe query Cipherazzi
sc.exe stop Cipherazzi
sc.exe start Cipherazzi
```

`--install` copies the collector into System32, registers automatic startup under LocalSystem, and starts the service. Supplied capture options persist in its service command line. The default journal and log paths match the MSI installation. `--db <file>` persists an absolute custom journal path; prepare that directory and its permissions first.

Changing the standalone service's binary or capture options requires `--uninstall` followed by installation with the desired arguments. Run uninstallation from the matching collector binary in an elevated console:

```powershell
.\Cipherazzi.Collector.exe --uninstall
```

Journals and logs remain available after uninstallation. A collector executable still in use can be scheduled for removal at reboot.

## Interactive collection and replay

These examples use published executables in the current directory and an existing writable journal directory:

```powershell
.\Cipherazzi.Collector.exe --db .\captures\capture.db
.\Cipherazzi.Collector.exe --db .\captures\short.db --duration 60
.\Cipherazzi.Collector.exe --list-sources
.\Cipherazzi.Collector.exe --db .\captures\replay.db --replay .\capture.pcap --no-process
```

Live collection requires an elevated console. Omit `--duration` for continuous collection; duration values must be positive. Press Ctrl+C to drain and stop. The interactive default journal is `cipherazzi.db` in the current directory.

Replay accepts classic PCAP with Ethernet, raw IP, raw IPv4, or raw IPv6 records, including microsecond or nanosecond timestamps. Convert PCAPNG before replay. Replayed packets do not establish historical local process ownership; `--no-process` avoids unnecessary attribution work. Use a new journal when keeping separate experiments or replay evidence.

## Collector options

| Option | Behavior / default |
| --- | --- |
| `--db <file>` | SQLite journal; interactive default `cipherazzi.db`, service default `%ProgramData%\Cipherazzi\capture.db`. |
| `--duration <seconds>` | Stop an interactive capture after a positive duration; omitted means continuous. |
| `--source <id>` | Select a Packet Monitor component from `--list-sources`; repeat to select several. Default sources are network interfaces. |
| `--loopback-only` | Capture same-host TCP/UDP with the packaged signed driver and no Packet Monitor sources; cannot be combined with `--source`. |
| `--no-loopback` | Capture network sources without the loopback driver. By default both are captured. |
| `--max-flows <n>` | Maximum tracked TCP/UDP flows; default 32,768, range 1–1,000,000. |
| `--buffer-mb <n>` | Protocol inspection/reassembly budget; default 128 MiB, range 1–4096 MiB. |
| `--retention-days <n>` | Age cleanup; default 30 days, range 0–36,500. Zero disables age cleanup. |
| `--retention-mb <n>` | Live journal page target; default 512 MiB, range 0–1,048,576 MiB. Zero disables size cleanup. |
| `--replication-required` | Protect records until upload acknowledgement, including before the first relay destination registers. |
| `--no-process` | Disable local process attribution. |
| `--classify-raw` | Enable optional high-entropy sampling of otherwise unidentified TCP/UDP traffic. |
| `--schannel` | Subscribe to emitted Schannel and CAPI2 events. |
| `--jfr-directory <dir>` | Watch an existing directory of atomic Java Flight Recorder JSON exports. |
| `--endpoint-directory <dir>` | Watch an existing directory of atomic TLS/raw endpoint reports. |
| `--import-jfr <file>` | Import a JFR JSON export without packet capture. |
| `--replay <file>` | Replay a classic PCAP instead of live capture. |
| `--list-sources` | List the loopback source and available Packet Monitor components. |
| `--install` / `--uninstall` | Install or remove the standalone service. |
| `--help` / `-h` | Print usage and capture limitations. |

Service installation supports continuous live capture options; replay, duration, source listing, and one-off JFR import cannot be service installation modes. See [endpoint telemetry](EndpointTelemetry.md) before enabling optional sources.

## Automatic local retention

The collector periodically prunes eligible connection metadata, endpoint events, certificate links, and unreferenced certificates. Age cleanup uses activity timestamps and includes a five-minute quiet period. Connections must have ended or belong to a stopped capture session. Size pressure can prune eligible records younger than the age limit, oldest first. Age cleanup also waits until the containing capture session is old enough.

Retention protects active connections and records awaiting acknowledgement from every registered relay or event publishing destination. With `--replication-required`, records are also protected before a destination first registers. Without that option, ordinary retention can remove old records before a destination has ever been configured. Keep this distinction in mind when provisioning collectors ahead of central connectivity.

For example, a standalone service configured for upload protection and a larger local journal target can be installed with:

```powershell
.\Cipherazzi.Collector.exe --install --replication-required --retention-days 30 --retention-mb 2048
```

The size target counts live SQLite pages. Allocated database space and the write-ahead log can exceed it; reclamation is incremental and readers can delay it. Active data, a protected upload backlog, and the quiet period can also keep live pages above the target. This is a cleanup target rather than a disk quota.

Use **Capture health** on a local journal to inspect live page size, pruned counts, and blocked cleanup. Investigate unavailable relay or event publishing destinations and provide disk capacity when uploads are protected. Destination registration remains relevant after the sending process stops. The event publisher supports `--unregister` for retiring its own destinations; the database relay has no destination-unregistration command. Removing acknowledgement records manually can permit data loss.

Setting both retention values to zero disables automatic pruning. This also requires an independent storage plan. Local cleanup does not propagate deletes to remote databases: configure central retention and backups separately.

## Central metadata replication

Create a destination database in SQL Server or PostgreSQL. The relay initializes the `cipherazzi` schema, tables, and indexes, so its initialization account needs the appropriate schema creation permissions. Use a separate read account for the viewer.

Provision an account-protected connection file with the relay. The command prompts for a connection string without echoing it. Use certificate-validated encrypted database connections; SQL Server also supports integrated authentication.

```powershell
.\Cipherazzi.Relay.exe --protect-connection C:\CipherazziConfig\relay.credential --provider sqlserver
.\Cipherazzi.Relay.exe --source "$env:ProgramData\Cipherazzi\capture.db" --provider sqlserver `
    --connection-file C:\CipherazziConfig\relay.credential
```

For PostgreSQL, use `--provider postgresql` for both commands. Add `--local-system` to the provisioning command from an elevated console when preparing credentials for the default MSI relay service. For another service account, provision while running as that account. A connection file is usable only by its owning account; do not put connection strings in service arguments or configuration JSON.

The relay requires write access to the local journal to register and advance durable acknowledgements. Its remote cursor advances in the same transaction as the uploaded rows; the local acknowledgement advances after remote commit. Interrupted uploads resume using these cursors. `--once` catches up and exits; without it the relay runs until Ctrl+C and retries interrupted connections.

The MSI Relay feature installs and starts `CipherazziRelay` using the file supplied in `RELAYCONFIG`. Set `source`, `provider`, and `connection-file` in that JSON file. For interactive operation, use the command above or `--config <file>`.

Provision a separate read connection for the viewer account and open it with:

```powershell
.\Cipherazzi.Viewer.exe --connection-file C:\CipherazziConfig\viewer.credential
```

The viewer's **Connect** dialog also supports local SQLite, SQL Server, and PostgreSQL. It does not store database passwords in `Viewer.config`. Require encrypted connections with certificate verification for central metadata; the dialog's certificate-trust override relaxes that verification.

## Event publishing

Use [event publishing](Publishing.md) to send selected connection, endpoint, and capture health metadata to a TLS syslog receiver or the Windows Application log. Publishing runs separately from collection, requires journal write access for its cursors, and remains disabled until configured and started. The MSI Collector feature registers the Windows event source; the optional Publisher feature starts `CipherazziPublisher` using the file supplied in `PUBLISHERCONFIG`. Include publisher output, delivery recovery, receiver capacity, and protected backlog storage in deployment planning.

## Resource planning and operations

Pilot representative workstations and busy servers with their normal network interfaces, offloads, storage, antivirus, and endpoint sources. Measure idle collection, startup, normal work, sustained bulk transfers, concurrent handshakes, and interrupted central connectivity. Use [the performance harnesses](../tests/README.md#performance) to make repeatable comparisons.

The 128 MiB setting bounds protocol inspection storage, not the entire process working set or Windows capture buffers. Increasing flow or buffer limits trades memory for coverage under load. Increasing the buffer does not increase the Packet Monitor streaming packet-size limit or prevent operating-system capture loss. Raw classification and optional endpoint sources add work; enable them according to the information required.

For local SQLite capture journals, use a local disk with appropriate permissions and capacity. Use the relay for centralization. Back up a running SQLite journal through a SQLite-aware backup mechanism, or stop its writer cleanly before copying; committed state may still depend on the `-wal` file.

Monitor **Capture health** for capture, packet queue, database queue, process, and telemetry losses; truncated or malformed packets; flow and reassembly limits; and a recent session heartbeat. Counters that increase during a workload indicate incomplete evidence. The session heartbeat and its counters are written with each batch of observations and every five seconds while nothing new is recorded; the viewer reports no recent heartbeat after ten seconds. A quiet display can also result from the wrong capture source, loopback traffic, or an unavailable endpoint source. Consult `service.log` for service startup or capture failures.

There is no universal CPU, memory, storage, or loss-free throughput guarantee. Practical limits depend on the target operating system, interface behavior, concurrent flows, handshake rate, and storage latency. Treat unusually extreme workloads outside the intended deployment profile as documented capacity limits, and retain the measured limits for each supported enterprise profile.

## Security and data access

The collector persists protocol metadata, identities, endpoint report provenance, sample statistics, and public certificate DER. Application payload samples and reassembly bytes are transient inspection data; Cipherazzi does not persist application payloads or private keys. It does not decrypt application traffic or replace endpoint trust validation.

The default service journal directory grants SYSTEM and Administrators full access and local Users read/execute access. Metadata can include hostnames, addresses, process paths, accounts, and certificate subjects. Tighten read access if that inventory is sensitive. Custom journal and report directories need explicit permissions appropriate to their writers and readers.

Treat endpoint report writers as trusted sources: anyone able to write reports can influence recorded completion, algorithm, certificate, or verification evidence. Keep report directories writable only by the intended reporters and administrators. See [report contracts and provenance](EndpointTelemetry.md#application-reports).

Local viewing is read-only, and native certificate opening checks the stored DER against its recorded SHA-256 fingerprint. These measures do not authenticate the journal as a whole. Protect the collector binary, journal writers, relay credentials, central database, and backups through the enterprise's ordinary access controls.
