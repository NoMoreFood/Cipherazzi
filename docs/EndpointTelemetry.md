# Endpoint telemetry

Endpoint telemetry adds public evidence from the application or operating system. It can supplement encrypted network fields and same-host traffic, with provider-specific limitations. Enable only the sources required by the deployment and preserve their provenance when interpreting results.

## Windows events

Enable the collector subscription with `--schannel`:

```powershell
.\Cipherazzi.Collector.exe --db .\capture.db --schannel
```

This subscribes to emitted Schannel and CAPI2 events. Event availability depends on Windows logging configuration and the application's use of those providers. The collector does not change machine event-logging policy, and a subscription does not ensure that every handshake or authentication detail will be emitted. Inspect **Endpoint telemetry** and **Capture health** for observed events and source errors.

## Java Flight Recorder

Java Flight Recorder JSON exports can be imported directly or watched by directory:

```powershell
.\Cipherazzi.Collector.exe --db .\java-import.db --import-jfr .\events.json
```

Or watch an export directory:

```powershell
$javaReports = Join-Path $env:LOCALAPPDATA 'Cipherazzi\JavaReports'
New-Item -ItemType Directory -Path $javaReports -Force | Out-Null
.\Cipherazzi.Collector.exe --db .\capture.db --jfr-directory $javaReports
```

Java events provide the fields emitted by that JVM. They are not a general source of all TLS 1.3 CertificateVerify schemes or every application's completion state.

## Application reports

An instrumented application or trusted adapter can publish reports to a directory watched by `--endpoint-directory`:

```powershell
.\Cipherazzi.Collector.exe --db .\capture.db --endpoint-directory .\endpoint-reports
```

Create and secure the directory before starting collection. Write each complete report to a temporary file and rename it atomically to a `.json` file in that directory. Partial writes can be rejected. Use the published contracts as the source of field names and bounds:

| Contract | Use |
| --- | --- |
| [EndpointReport.schema.json](../Source/Collector/EndpointReport.schema.json) | `cipherazzi.endpoint/1`: TLS, QUIC, or DTLS handshake and established-connection evidence. |
| [RawEndpointReport.schema.json](../Source/Collector/RawEndpointReport.schema.json) | `cipherazzi.raw/1`: reported raw TCP/UDP encryption evidence. |

The published distribution and MSI include the TLS endpoint schema. The raw report schema is available in the source tree.

Both contracts identify the provider, PID, process start time, report time, endpoint role, transport, and success. Timestamps use Unix-epoch microseconds. Process lifetime, socket identity, and operation timing help distinguish reused PIDs and sockets. Keep host clocks and reporter timestamps consistent.

TLS handshake reports require `handshake_started_us`. An established-connection observation uses `observation: "connection"`, requires success, and omits handshake timing. Socket endpoints may be omitted when unavailable; those reports remain unassociated with packets. `process_scope: "application"` records the reporting application without claiming it owns the TLS socket. Unknown roles and transports remain unknown.

Successful TLS reports require a cipher ID and a wire version, except that QUIC may omit an unspecified TLS version. Successful DTLS reports use `0xfeff`, `0xfefd`, or `0xfefc` as the wire version, encoded as a JSON integer. Optional fields include the selected group, peer and local handshake signature schemes, selected ALPN, peer verification, and public server/client certificate chains as base64 DER. QUIC packet association also needs the original destination connection ID; reports without it remain unassociated.

Raw reports require both socket endpoints, `operation_started_us`, the algorithm, mode, and key size in bits. These are reported application properties; the entropy classifier cannot infer them. Use only public metadata in either contract: report no application plaintext, private keys, traffic secrets, or session key material.

Reports retain their provider provenance and can remain unmatched when the corresponding packet observation is unavailable or ambiguous. A success report, a reported verification decision, and a matched network observation are separate pieces of evidence. Inspect their correlation in the viewer rather than assuming that every report proves every connection field.

Keep report directories writable only by trusted reporters and administrators. A process able to submit a valid report can influence the recorded evidence. Parsing bounds, schema checks, and correlation do not authenticate a reporter. Protect report outputs and remove obsolete files through the reporter's storage policy; journal retention does not manage the report directory.

Use the optional [event publisher](Publishing.md) to send selected stored endpoint metadata to syslog or the Windows Application log. Its `endpoints` event filter includes reported results and bounded evidence without exporting raw provider XML, full report bodies, or certificate DER. Configure report collection independently of event publishing.
