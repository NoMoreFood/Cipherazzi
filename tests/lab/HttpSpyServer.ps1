#requires -Version 7
param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][string]$Identity,
    [Parameter(Mandatory)][string]$Ready, [int]$Port = 443)

# HTTPS fixture for the live HTTP Spy lab: plain, chunked-with-trailer, connection-delimited, and echo responses.
# It uses PowerShell 7's TLS shutdown support, one connection at a time.
$ErrorActionPreference = 'Stop'
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Identity, 'lab',
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet)
$listener = [Net.Sockets.TcpListener]::new([IPAddress]::Parse($Address), $Port)
$listener.Start()
Set-Content -LiteralPath $Ready -Value 'ready' -Encoding ascii

function Send($Stream, [string]$Text, [byte[]]$Body = @())
{
    $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
    if ($Body.Length) { $Stream.Write($Body, 0, $Body.Length) }
    $Stream.Flush()
}

function ReadHead($Stream)
{
    $head = [Text.StringBuilder]::new()
    $one = [byte[]]::new(1)
    while (-not $head.ToString().EndsWith("`r`n`r`n"))
    {
        if ($Stream.Read($one, 0, 1) -ne 1 -or $head.Length -gt 65536) { return $null }
        [void]$head.Append([char]$one[0])
    }
    $head.ToString()
}

function ReadChunkLine($Stream)
{
    $line = [Text.StringBuilder]::new()
    while (-not $line.ToString().EndsWith("`r`n"))
    {
        $value = $Stream.ReadByte()
        if ($value -lt 0 -or $line.Length -gt 8192) { throw 'Incomplete chunk framing.' }
        [void]$line.Append([char]$value)
    }
    $line.ToString().TrimEnd("`r`n")
}

while ($true)
{
    $client = $listener.AcceptTcpClient()
    try
    {
        $client.ReceiveTimeout = 10000
        $stream = [Net.Security.SslStream]::new($client.GetStream(), $false)
        $stream.AuthenticateAsServer($certificate, $false, [Security.Authentication.SslProtocols]::Tls12, $false)
        while ($head = ReadHead $stream)
        {
            $lines = $head -split "`r`n"
            $method, $path = ($lines[0] -split ' ')[0, 1]
            $headers = @{}
            foreach ($line in $lines[1..($lines.Length - 1)])
            {
                if ($line -match '^([^:]+):\s*(.*)$') { $headers[$Matches[1].ToLowerInvariant()] = $Matches[2] }
            }
            $length = if ($headers.ContainsKey('content-length')) { [int]$headers['content-length'] } else { 0 }
            $chunked = $headers['transfer-encoding'] -eq 'chunked'
            if ($headers['expect'] -eq '100-continue' -and ($length -or $chunked))
            {
                Send $stream "HTTP/1.1 100 Continue`r`n`r`n"
            }
            $body = [byte[]]::new($length)
            for ($read = 0; $read -lt $length;)
            {
                $count = $stream.Read($body, $read, $length - $read)
                if ($count -le 0) { break }
                $read += $count
            }
            if ($chunked)
            {
                $length = 0
                while ($true)
                {
                    $count = [Convert]::ToInt32((ReadChunkLine $stream).Split(';')[0], 16)
                    if ($count -eq 0)
                    {
                        while ((ReadChunkLine $stream).Length) {}
                        break
                    }
                    if ($count -lt 0 -or $count + $length -gt 65536) { throw 'Fixture body limit exceeded.' }
                    $body = [byte[]]::new($count)
                    $stream.ReadExactly($body, 0, $count)
                    if ((ReadChunkLine $stream).Length) { throw 'Invalid chunk terminator.' }
                    $length += $count
                }
            }
            switch ($path)
            {
                '/chunked'
                {
                    Send $stream ("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nTransfer-Encoding: ChUnKeD`r`n" +
                        "Trailer: X-Trailer`r`n`r`n6`r`nfirst `r`n6`r`nsecond`r`n0`r`nX-Trailer: done`r`n`r`n")
                }
                '/close'
                {
                    Send $stream ("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n" +
                        "Connection: ClOsE`r`n`r`nends with the connection")
                    $stream.ShutdownAsync().GetAwaiter().GetResult()
                    $client.Close()
                    break
                }
                { $_ -in '/interrupted-close', '/interrupted-length', '/interrupted-chunked' }
                {
                    $framing = switch ($path)
                    {
                        '/interrupted-length' { "Content-Length: 20`r`n" }
                        '/interrupted-chunked' { "Transfer-Encoding: chunked`r`n" }
                        default { '' }
                    }
                    $partial = if ($path -eq '/interrupted-chunked') { "4`r`npart`r`n" } else { 'part' }
                    Send $stream "HTTP/1.1 200 OK`r`n${framing}Connection: close`r`n`r`n$partial"
                    $client.Close()
                    break
                }
                { $_ -in '/headers', '/headers-ok' }
                {
                    $count = if ($path -eq '/headers') { 66 } else { 48 }
                    $fields = (1..$count | ForEach-Object { "X-Fixture-${_}: " + ('a' * 1000) + "`r`n" }) -join ''
                    Send $stream "HTTP/1.1 200 OK`r`n${fields}Content-Length: 2`r`n`r`nok"
                }
                '/echo'
                {
                    $json = [Text.Encoding]::ASCII.GetBytes((@{ length = $length;
                        authorization = $headers['authorization'] } | ConvertTo-Json -Compress))
                    Send $stream "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`nContent-Length: $($json.Length)`r`n`r`n" $json
                }
                default
                {
                    Send $stream ("HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`nContent-Length: 2`r`n" +
                        "Connection: x-close, Keep-Alive`r`n`r`nok")
                }
            }
            if (-not $client.Connected) { break }
        }
    }
    catch {}
    finally { if ($stream) { $stream.Dispose() }; $client.Close() }
}
