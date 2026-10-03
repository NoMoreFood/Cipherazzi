# Syslog and Windows Event Log publishing

`Cipherazzi.Publisher.exe` publishes committed local journal metadata to a syslog receiver, the Windows Application event log, or both. Publishing is optional and runs in a separate process. The collector continues collecting when a destination is unavailable. Installing the MSI does not start a publisher or configure a receiver.

Use a local journal created by the collector. The publisher needs read/write access to the journal and its directory for durable cursors and SQLite sidecar files. The default service directory allows SYSTEM and Administrators to write; deploy publishing under an account with the required access. Prepare the receiver and choose the event kinds before enabling publishing across the fleet.

## Syslog

From a published or installed application directory:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514
```

Configure the receiver for [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424) messages with [RFC 5425](https://www.rfc-editor.org/rfc/rfc5425) octet-counted framing. The application name is `Cipherazzi`; message IDs are `CONNECTION`, `ENDPOINT`, and `HEALTH`. The message body is one JSON object. The default facility is `local0`; `--facility <0..23>` selects another facility.

TLS requires a valid server certificate for the destination hostname and an accepted trust chain. The publisher enables TLS 1.2 and TLS 1.3 and uses online certificate revocation checks. For an enterprise CA, supply a PEM certificate bundle or DER certificate:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514 --syslog-ca C:\CipherazziConfig\syslog-ca.pem
```

The supplied certificates define trust for this connection; they do not change Windows trust stores or disable hostname verification. Keep CA files under administrator control. A file can contain up to sixteen public CA certificates and must not exceed 1 MiB.

For mutual TLS, provision a client certificate and accessible private key in the publishing account's Windows certificate store:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514 --syslog-ca C:\CipherazziConfig\syslog-ca.pem `
    --client-certificate <certificate-thumbprint> --certificate-store LocalMachine
```

The certificate thumbprint can be SHA-1 or SHA-256. `LocalMachine` is the default store; `CurrentUser` selects the running account's personal store. Grant that account access to the private key. The publisher does not export the private key.

Plain TCP requires both a `tcp://host:514` destination and `--allow-plaintext-syslog`. It uses the same octet-counted framing and sends metadata without transport encryption. Use TLS for enterprise deployment. UDP syslog is unsupported.

## Windows Event Log

The MSI Collector feature registers the `Cipherazzi` source in the Application log. For standalone deployment, run source registration once from an elevated console with a collector binary containing the event message resources:

```powershell
.\Cipherazzi.Publisher.exe --register-event-source
```

Keep `Cipherazzi.Collector.exe` beside the publisher at a stable installed location, or supply its absolute path with `--event-message-file`. Source registration checks the message resources before creating the registry entries. It refuses to overwrite a source registered to a different message file. Message rendering requires that file to remain available.

Run Windows publishing alone or alongside syslog:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" --windows-events
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514 --windows-events
```

| Event ID | Metadata |
| --- | --- |
| 1001 | Connection negotiation and available process/certificate identifiers. |
| 1002 | Endpoint telemetry and selected reported evidence. |
| 1003 | Capture session health, counters, inspection limits, and status. |

Events render their JSON body in Event Viewer and expose it as the first event data value. Health snapshots use Warning when loss or inspection-limit counters are nonzero or the session status starts with `failed`. Endpoint results containing `failure` also use Warning; other events use Information. These levels do not evaluate viewer policies or classify all cryptographic risk.

Use Windows Event Forwarding to subscribe to Application events from this source and these IDs. Configure forwarding, Application log capacity, and retention through the enterprise's existing tooling. A different registered source can be selected with `--windows-event-source <name>`; use that same name for registration and publishing.

## Select events and resource limits

All three event kinds are enabled by default. For health and endpoint telemetry only:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514 --events endpoints,health
```

| Option | Default and purpose |
| --- | --- |
| `--poll-ms <100..10000>` | 1000 ms between journal reads when caught up. |
| `--health-seconds <5..3600>` | 60 seconds between unchanged-status health snapshots for a session. |
| `--max-events-per-second <1..10000>` | 250 events per second per destination. |
| `--once` | Catch up with committed snapshots and exit; destination failures return a nonzero exit code. |
| `--duration <1..86400>` | Stop a continuous publisher after the supplied number of seconds. |
| `--start-now` | Initialize a new destination cursor at the current revision. |
| `--unregister` | Remove selected destination cursors and their retention protection. |

Health snapshots depend on journal updates. A capture status change or a transition between zero and nonzero loss/inspection-limit counters bypasses the health interval. Regular counter updates are coalesced while the publisher runs; the health throttle resets on process restart.

The publisher processes batches of up to 128 events. It closes journal reads before delivering a batch and maintains separate workers, retries, and cursors for syslog and Windows events. Network connection, TLS authentication, and writes have a five-second deadline; continuous publishing retries interrupted destinations after three seconds. Successful startup, pauses, and recoveries are reported to the console. Deployment tooling should collect this output and supervise the process.

The publisher is a console application. Arrange startup, account permissions, process recovery, and configuration through deployment tooling; the MSI does not install a publishing service or scheduled task. Press Ctrl+C for a clean stop. Publishing adds no collector publishing work while the publisher is disabled.

## Delivery, cursors, and local retention

First use publishes available journal history unless `--start-now` is supplied. Each later run resumes its durable cursor. The syslog destination identity consists of transport, hostname, and port; Windows destination identity consists of log and source. Changing event filters affects future reads from that cursor and does not backfill event kinds skipped earlier. Run separate publisher processes for additional syslog destinations. Only one process can publish the same journal to the same destination at a time.

A registered destination protects records from local retention until its completed batches advance the acknowledgement. This protection persists while the publisher is stopped or a receiver is unavailable. It shares the collector's acknowledgement mechanism with database relay destinations. Protecting a backlog can let the journal exceed its size target; provision disk space and monitor delivery failures. `--replication-required` also protects records before the first destination registers.

Stop the publisher before retiring a destination, then remove only that destination's protection:

```powershell
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --syslog tls://siem.example:6514 --unregister
.\Cipherazzi.Publisher.exe --source "$env:ProgramData\Cipherazzi\capture.db" `
    --windows-events --unregister
```

Unregistering makes pending data eligible for normal local cleanup. Reusing that destination creates a new cursor. Choose `--start-now` if available history should be skipped.

Interrupted batches can be sent again. The stable JSON `id` supports receiver deduplication across retries and destinations. Syslog acknowledges transport writes locally; it has no receiver application acknowledgement, so a completed write does not prove that the SIEM stored the event. Windows delivery acknowledges the local Event Log write and does not confirm subsequent forwarding. These outputs do not provide an exactly-once audit transport.

## Event data and evidence limits

[Event.schema.json](../publisher/Event.schema.json) defines the envelope. Each object contains `schema` (`cipherazzi.event/1`), a stable hexadecimal `id`, `database_id`, journal `revision`, `type`, event `timestamp_us`, `computer`, and a `payload`. Timestamps are Unix microseconds from the journal record. Connection payloads contain recorded endpoints, protocol/cipher/group/authentication fields, process identifiers and paths, connection state, and the public certificate fingerprint. Endpoint payloads contain provider, operation, result, correlation fields, and selected evidence. Health payloads contain session status and counters.

Each JSON body is limited to 16 KiB in UTF-8. Text fields are capped at 1024 characters, selected evidence values are bounded, and oversized bodies use a smaller summary. `truncated: true` marks clipped or omitted metadata. Unreadable provider metadata is marked `metadata_unavailable` in the payload. Publishing excludes certificate DER, raw provider XML, full endpoint report bodies, packet payloads, and private keys. Hostnames, addresses, process paths, and other inventory metadata remain sensitive; restrict access to receivers and event logs.

Events describe the latest committed snapshots visible when read. Intermediate updates can be coalesced before publishing, and connection snapshots can precede completion or certificate evidence. Use identifiers and revisions to interpret later updates. Publishing does not add detection coverage, infer encrypted authentication, or turn unknown evidence into completion. See [capture coverage](Coverage.md) and [endpoint telemetry](EndpointTelemetry.md).
