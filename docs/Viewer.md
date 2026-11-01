# Using the viewer

## Connect and investigate

Launch `Cipherazzi.Viewer.exe <capture.db>` to open a local journal, or use **Connect** to select SQLite, SQL Server, or PostgreSQL. A local journal is opened read-only and can be viewed while the collector runs. The collector and viewer have independent lifetimes.

The toolbar provides **Connect**, **Refresh**, **Live**, **Filters**, **Options**, **Capture health**, and **Help**, with context-specific launch and export actions. Ctrl+O opens Connect, F5 refreshes, and F1 or Help opens the [Cipherazzi GitHub home](https://github.com/NoMoreFood/Cipherazzi) in the default browser. Capture coverage by computer is available inside **PQC readiness**.

Use **Search** for SNI, address, process, cipher, or group, and **Protocol** to select an observed protocol. Enable **Partial exchanges** to show only incomplete exchanges. **Filters** adds explicit UTC dates, field conditions, and saved searches, with separate scopes for connections and endpoint telemetry. Connections are paged newest first, with 250 rows per page by default. Use the navigation controls to inspect older observations; live updates pause while browsing older connection pages.

**Launch collector** appears while no collector is running. Choose live capture or replay, the journal, capture sources, and optional HTTP Spy settings, then review the command preview. Live capture requests administrator rights. The collector runs in its own console; closing the viewer leaves it running. See [collection options](Deployment.md#collector-options) for command-line and service workflows.

Press Ctrl+F to focus Search and select the current query. Press Escape while Search has focus to clear the query without changing the protocol or partial-exchange filters.

Select a connection to populate its details. Expand a section to inspect negotiation stages, algorithms, process ownership, certificate metadata, findings, and endpoint provenance. For TLS evidence, source is the client and destination is the server; these roles do not imply that source is the local machine. Unavailable remote process information is expected.

Use a detail property's description to understand its meaning. The detail grid's context menu can copy a value or all properties, expand all evidence sections, or collapse them for a compact overview. Column visibility, order, and width can be configured through Options or the investigation grids' column-header menus.

The inspector also presents **SSH host key**, **SMB negotiation**, **RDP negotiation**, **TDS framing**, and **DTLS-SRTP** evidence when recorded. SMB, RDP, and TDS have protocol filter entries; a TDS/RDP exchange with visible TLS hellos is classified under its TLS version while retaining application metadata. SSH fingerprints are hexadecimal SHA-256, not an assertion of host trust. SMB capabilities, selected security algorithms, and observed encrypted framing are separate facts. DTLS-SRTP profile selection does not prove that media was sent.

## Open and export certificates

In a connection's details pane, click the open glyph at the right edge of a certificate heading, such as **Server 1 certificate** or **Server 2 certificate**. It opens that specific public certificate in the Windows certificate viewer. The action is available while the section is collapsed when a unique stored certificate is linked to that heading.

In **Certificates**, double-click a certificate row or select it and choose **Windows certificate viewer…**. Use **Export certificate…** to save its public certificate as DER or PEM. The inventory combines packet and endpoint evidence and counts a matched report with its negotiation. **Observed usage** shows the computer, applications, and evidence source. Application-scoped reports retain the reporting application without assigning it a client or server role. Unreported certificate roles and chain positions remain unknown; position 1 is the leaf when a chain position is available.

Certificate opening and export require stored DER data. The viewer validates its SHA-256 fingerprint before opening or exporting it. A missing certificate or fingerprint mismatch produces an error. Selecting a different capture cancels a pending detail-pane open action.

Seeing a certificate establishes public certificate evidence. It does not establish that the connection completed, the peer was trusted, or a particular encrypted handshake signature was used. Windows may evaluate the certificate using the viewing machine's trust environment, which can differ from the endpoint that made the connection.

## Views

| View | Use |
| --- | --- |
| **Connections** | Inspect individual observations, hello selections, partial exchanges, process ownership, and evidence. |
| **Visualizations** | Explore aggregate protocol and algorithm distributions. |
| **Analytics** | Group and filter observations, inspect trends and findings, and export displayed analytics. |
| **Endpoint telemetry** | Inspect reported events and their provider, process, timestamps, and correlation evidence. |
| **PQC readiness** | Compare key establishment, authentication, completion, certificate evidence, capture coverage, and migration baselines. |
| **Certificates** | Browse unique public certificates and their packet and endpoint usage. |
| **Policies** | Configure scoped requirements and inspect observed violations and insufficient evidence. |
| **HTTP Spy** | Browse decoded requests and responses from the separate local HTTP store, inspect payloads, and export HAR. |

Read [coverage and limitations](Coverage.md) when interpreting empty fields, unknown classifications, or partial records.

## Export and decoded messages

**Bulk export** in Connections, Endpoint telemetry, or Policies writes matching evidence to CSV or JSONL across all pages. The active filters apply. Policy exports evaluate the configured policies over the matching observations. Use the export button again to cancel; incomplete output does not replace the destination file. Analytics has a separate action for its displayed results.

**HTTP Spy** requires a local journal collected with `--httpspy`; replicated server databases do not contain decoded messages. For an elevated collector's private store, run the viewer as an administrator. Search filters the message list. Select a message to view its request, response, timing, and body truncation notes; choose the payload representation, save a body, or preview a supported image. **Export HAR** exports all matching messages, including retained body data. Treat HAR files and saved bodies as sensitive. Collection modes and limits are described in [HTTP Spy setup](Deployment.md#http-spy).

## Post-quantum readiness and baselines

Choose a **Time range** and **Group by** dimension to compare observed application or peer cohorts. Post-quantum key establishment, handshake authentication, and certificate-chain signatures are separate properties. A hybrid key exchange can still use classical authentication. A post-quantum certificate signature alone does not prove a post-quantum handshake signature.

Unknown evidence remains in the percentage denominator. Completion requires endpoint completion evidence; visible server hello selections alone do not establish it. TLS 1.3 authentication and selected ALPN generally need an appropriate endpoint source. DTLS cleartext negotiation contributes readiness evidence, with encrypted authentication remaining unknown.

Use **Capture baseline…** to save a JSON migration baseline and **Load baseline…** to compare it with the current scope. **Min. samples** controls the minimum cohort observations considered for comparisons. Changes describe the captured populations and evidence; they do not establish an attack or independently explain a change in coverage.

## Policies and findings

All enabled policies matching an observation apply. Policies can scope by computer, process name or path, and server name, using case-insensitive wildcard patterns. The process role selects the client, server, or either endpoint.

Choose a policy protocol: TLS (including DTLS and QUIC TLS evidence), SSH, SMB, WireGuard, IKEv2, OpenVPN, or LDAP. TLS requirements cover minimum version, post-quantum key establishment, standardized groups, approved group and signature IDs, certificate roles and algorithm OIDs, endpoint completion, and reported peer verification. Other protocols expose their applicable algorithm, signing, encryption, or authentication requirements. Algorithm ID lists accept decimal or `0x` hexadecimal values. Certificate algorithm lists use numeric OIDs.

The default **PQC migration** policy is enabled and requires TLS 1.2 or later, post-quantum key establishment, standardized PQ groups, and endpoint completion. It does not require post-quantum client or server authentication by default. Review these defaults for the intended migration stage.

Results distinguish **Violation** from **Insufficient evidence**. Missing endpoint authentication or completion evidence must be investigated as a coverage gap. A policy result is an assessment of available evidence, not a cryptographic verification of the application.

General connection findings have separate defaults: minimum TLS 1.2, minimum finite-field DH size 2048 bits, and warnings for missing extended master secret where applicable. Change these through viewer configuration when necessary. Policy configuration can be exported from the Policies view.

Fixed findings include legacy SSH or Kerberos algorithms, NTLMv1 or LM responses, SMB1, plaintext passwords or logins in supported protocols, unsigned LDAP sessions, Standard RDP Security, HTTP authentication sent in clear, and unencrypted or login-only TDS protection. They reflect observed selections, messages, or usage; offers alone do not establish a finding. An absence of findings does not establish stronger protection when relevant messages were not captured.

## Settings

Use **Options** for theme, live refresh, paging, analytics, and columns. Light, Dark, and System themes are supported. Ordinary saved preferences are stored in `%LOCALAPPDATA%\Cipherazzi\Viewer.config`.

Without `--config`, settings load in this order: built-in defaults, `Cipherazzi.Viewer.config` beside the executable, then the per-user file. A malformed file is rejected as a complete candidate and a warning is shown; valid settings already loaded remain available.

An explicit configuration is applied on top of built-in defaults and excludes the normal executable and per-user files:

```powershell
.\Cipherazzi.Viewer.exe .\capture.db --config .\team-viewer.config
```

Options still save to the ordinary per-user location. They do not rewrite the explicit configuration; manage that file separately for repeatable launches. Database connection credentials are not stored in the viewer settings file.

The [shipped configuration](../Source/Viewer/Cipherazzi.Viewer.config) contains the complete column and policy examples. Key settings are:

| Setting | Default | Accepted values |
| --- | --- | --- |
| `theme` | `System` | `System`, `Light`, `Dark` |
| `live` | `true` | `true`, `false` |
| `showHttp` | `true` | `true`, `false`; include ordinary HTTP metadata in connection investigations |
| `showLoopback` | `true` | `true`, `false`; include same-host observations in connection investigations |
| `pollMilliseconds` | 250 | 100–10,000 |
| `pageSize` | 250 | 50–2000 |
| `analyticsMinutes` | 1440 | 0–525,600; zero means all time |
| `analyticsRefreshSeconds` | 5 | 2–300 |
| `topGroups` | 20 | 5–100 |
| `baselineMinimumSamples` | 5 | 1–1,000,000 |
| `findings minimumTls` | 771 | 768–772, corresponding to SSL 3.0 through TLS 1.3 |
| `findings minimumDhBits` | 2048 | 512–16,384 |
| `findings warnMissingEms` | `true` | `true`, `false` |

Configuration files are limited to 256 KiB. Larger page sizes, wider time windows, and faster polling increase investigation work; choose settings appropriate to the journal and database location.
