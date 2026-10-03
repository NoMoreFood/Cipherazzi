const activity = Cc['@mozilla.org/network/http-activity-distributor;1'].getService(Ci.nsIHttpActivityDistributor);
const reports = [], seen = new Set();
const errors = Cc['@mozilla.org/nss_errors_service;1'].getService(Ci.nsINSSErrorsService);
let dropped = 0, unavailable = 0, queuedBytes = 0;

function queue(report, key)
{
    if (seen.has(key))
        return;
    seen.add(key);
    if (seen.size > 4096)
        seen.delete(seen.values().next().value);
    const bytes = JSON.stringify(report).length;
    if (reports.length >= 128 || queuedBytes + bytes > 4 * 1024 * 1024)
    {
        ++dropped;
        return;
    }
    queuedBytes += bytes;
    reports.push(report);
}

// Enable concrete channel endpoints without inspecting request headers or application streams.
const activityObserver = {
    QueryInterface: ChromeUtils.generateQI(['nsIHttpActivityObserver']),
    get isActive() { return true; },
    observeActivity() {}
};

function encodeCertificate(certificate)
{
    const bytes = certificate.getRawDER();
    if (!bytes.length || bytes.length > 262144)
        return null;
    let value = '';
    for (let offset = 0; offset < bytes.length; offset += 4096)
        value += String.fromCharCode(...bytes.slice(offset, offset + 4096));
    return btoa(value);
}

// Read negotiated TLS evidence from the browser's public channel and security interfaces.
const observer = {
    QueryInterface: ChromeUtils.generateQI(['nsIObserver']),
    observe(subject)
    {
        try
        {
            const channel = subject.QueryInterface(Ci.nsIHttpChannel);
            if (!channel.URI.schemeIs('https') || !channel.securityInfo)
                return;
            const security = channel.securityInfo.QueryInterface(Ci.nsITransportSecurityInfo);
            const success = security.errorCode === 0;
            if (success)
            {
                try { if (!security.cipherName) return; }
                catch (_) { return; }
            }
            const internal = subject.QueryInterface(Ci.nsIHttpChannelInternal);
            const timing = subject.QueryInterface(Ci.nsITimedChannel);
            const started = timing.secureConnectionStartTime, timestamp = timing.connectEndTime;
            if (!started || timestamp < started || Date.now() * 1000 - started > 120000000)
                return;
            const pid = internal.isLoadedBySocketProcess ?
                Services.io.socketProcessId : Services.appinfo.processID;
            if (!pid)
                return;
            let local, remote;
            try
            {
                const source = { address: internal.localAddress, port: internal.localPort };
                const target = { address: internal.remoteAddress, port: internal.remotePort };
                if (source.address && target.address && source.port > 0 && target.port > 0)
                {
                    local = source;
                    remote = target;
                }
            }
            catch (_) {}
            const key = JSON.stringify([pid, local, remote, started, security.errorCode]);
            const chain = [];
            let total = 0;
            for (const certificate of security.handshakeCertificates.slice(0, 16))
            {
                const encoded = encodeCertificate(certificate);
                if (encoded === null || (total += encoded.length * 3 / 4) > 1048576)
                    break;
                chain.push(encoded);
            }
            const report = {
                schema: 'cipherazzi.endpoint/1', provider: 'Firefox/NSS', pid,
                handshake_started_us: started, timestamp_us: timestamp,
                role: 'client', process_scope: 'endpoint', transport: 'Unknown', success,
                server_name: channel.URI.asciiHost, server_certificates_der: chain
            };
            if (local)
                Object.assign(report, { local, remote });
            if (success)
            {
                const alpn = security.negotiatedNPN;
                Object.assign(report, {
                    transport: alpn.startsWith('h3') ? 'QUIC' : 'TCP',
                    peer_verified: security.succeededCertChain.length > 0,
                    tls_version: security.protocolVersion + 768, cipher_name: security.cipherName,
                    group_name: security.keaGroupName, signature_name: security.signatureSchemeName,
                    selected_alpn: alpn, session_resumed: security.resumed
                });
            }
            else
            {
                report.error_code = security.errorCode;
                report.error_name = security.errorCodeString;
                if (errors.isNSSErrorCode(security.errorCode) &&
                    errors.getErrorClass(errors.getXPCOMFromNSSError(security.errorCode)) ===
                    Ci.nsINSSErrorsService.ERROR_CLASS_BAD_CERT)
                    report.peer_verified = false;
            }
            queue(report, key);
        }
        catch (_) { ++unavailable; }
    }
};

// Capture stopped requests independently of document navigation and error-page rendering.
activity.addObserver(activityObserver);
Services.obs.addObserver(observer, 'http-on-examine-response');
Services.obs.addObserver(observer, 'http-on-before-stop-request');
globalThis.cipherazziCapture = {
    drain()
    {
        const result = { reports: reports.splice(0), dropped, unavailable };
        dropped = unavailable = 0;
        queuedBytes = 0;
        return result;
    },
    stop()
    {
        Services.obs.removeObserver(observer, 'http-on-examine-response');
        Services.obs.removeObserver(observer, 'http-on-before-stop-request');
        activity.removeObserver(activityObserver);
        seen.clear();
        return this.drain();
    }
};
return { active: true };
