# Endpoint telemetry

Endpoint telemetry adds public evidence from the application or operating system. It can supplement encrypted network fields and same-host traffic, with provider-specific limitations. Enable only the sources required by the deployment and preserve their provenance when interpreting results.

## Windows events

Enable the collector subscription with `--schannel`:

```powershell
.\Cipherazzi.Collector.exe --db .\capture.db --schannel
```

This subscribes to emitted Schannel and CAPI2 events. Event availability depends on Windows logging configuration and the application's use of those providers. The collector does not change machine event-logging policy, and a subscription does not ensure that every handshake or authentication detail will be emitted. Inspect **Endpoint telemetry** and **Capture health** for observed events and source errors.

## Java Flight Recorder

Use a JDK containing `jcmd.exe` and `jfr.exe`, with permission to attach to the selected JVM. The watcher configures TLS handshake, X.509 certificate, and X.509 validation events for that JVM and atomically publishes JSON exports. Recording storage is bounded by maximum age and size. The watcher stops its own recording and cleans up its staging directory on exit.

In these published-directory examples, set `$javaProcessId` to the target JVM's PID and `$javaHome` to its compatible JDK directory. Prepare a report directory with permissions for that reporter and the collector:

```powershell
$javaProcessId = 1234
$javaHome = 'C:\Java\jdk'
$javaReports = Join-Path $env:LOCALAPPDATA 'Cipherazzi\JavaReports'
New-Item -ItemType Directory -Path $javaReports -Force | Out-Null
.\Watch-Java.ps1 -ProcessId $javaProcessId -JavaHome $javaHome -OutputDirectory $javaReports
```

In a separate elevated collector console under the same account, point `--jfr-directory` to the same directory. The collector needs the directory to exist when it starts. When service and reporter accounts differ, use a shared, explicitly secured path:

```powershell
$javaReports = Join-Path $env:LOCALAPPDATA 'Cipherazzi\JavaReports'
.\Cipherazzi.Collector.exe --db .\capture.db --jfr-directory $javaReports
```

The watcher defaults to a five-second export interval and runs until stopped. `-IntervalSeconds` accepts 2–60; `-DurationSeconds` accepts 0–86,400, with zero meaning indefinite. If `-JavaHome` is omitted, it uses `JAVA_HOME` or locates `jcmd.exe` on PATH. It attaches only to the requested process.

A one-off JFR JSON export can be imported without packet capture:

```powershell
.\Cipherazzi.Collector.exe --db .\java-import.db --import-jfr .\events.json
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
| [EndpointReport.schema.json](../collector/EndpointReport.schema.json) | `cipherazzi.endpoint/1`: TCP TLS or QUIC handshake evidence. |
| [RawEndpointReport.schema.json](../collector/RawEndpointReport.schema.json) | `cipherazzi.raw/1`: reported raw TCP/UDP encryption evidence. |

The published distribution and MSI include the TLS endpoint schema. The raw report schema is available in the source tree.

Both contracts identify the provider, PID, process start time, operation start time, report time, local and remote socket endpoints, endpoint role, transport, and success. TLS uses `handshake_started_us`; raw encryption uses `operation_started_us`. Timestamps use Unix-epoch microseconds. Process lifetime and operation timing help distinguish reused PIDs and sockets. Keep host clocks and reporter timestamps consistent.

Successful TLS reports require a TLS version and cipher ID. Optional fields include the selected group, peer and local handshake signature schemes, selected ALPN, peer verification, and public server/client certificate chains as base64 DER. QUIC reports also require the original destination connection ID. Use only public metadata: report no application plaintext, private keys, traffic secrets, or session key material.

Raw reports require the algorithm, mode, and key size in bits. These are reported application properties; the entropy classifier cannot infer them. TLS endpoint reports currently accept TCP and QUIC transports; DTLS completion requires a separate supported source.

Reports retain their provider provenance and can remain unmatched when the corresponding packet observation is unavailable or ambiguous. A success report, a reported verification decision, and a matched network observation are separate pieces of evidence. Inspect their correlation in the viewer rather than assuming that every report proves every connection field.

Keep report directories writable only by trusted reporters and administrators. A process able to submit a valid report can influence the recorded evidence. Parsing bounds, schema checks, and correlation do not authenticate a reporter. Protect report outputs and remove obsolete files through the reporter's storage policy; journal retention does not manage the report directory.

Use the optional [event publisher](Publishing.md) to send selected stored endpoint metadata to syslog or the Windows Application log. Its `endpoints` event filter includes reported results and bounded evidence without exporting raw provider XML, full report bodies, or certificate DER. Configure report collection independently of event publishing.
