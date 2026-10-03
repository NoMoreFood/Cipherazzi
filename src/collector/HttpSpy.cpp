#include "HttpSpy.h"

#include <nghttp2/nghttp2.h>
#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <deque>
#include <map>
#include <stdexcept>

namespace Cipherazzi
{
size_t HttpExchange::memory() const
{
    return sizeof(*this) + transport.capacity() + scheme.capacity() + version.capacity() + method.capacity() +
        host.capacity() + target.capacity() + reason.capacity() + contentType.capacity() + state.capacity() +
        note.capacity() + requestHeaders.capacity() + responseHeaders.capacity() + requestBody.capacity() +
        responseBody.capacity();
}

struct HttpContext
{
    HttpSpy& owner;
    uint64_t flowId{};
    int64_t startedUs{};
    Endpoint client, server;
    const TlsDecryptor* tls{};
    std::string tunnelHost;
    uint32_t sequence{};
    bool emitted{}, tunnel{};

    HttpExchange create(int64_t timestampUs) const
    {
        HttpExchange exchange;
        exchange.flowId = flowId;
        exchange.flowStartedUs = startedUs;
        exchange.startedUs = timestampUs;
        exchange.client = client;
        exchange.server = server;
        exchange.scheme = tls ? "https" : "http";
        exchange.transport = tls && tls->version() ? versionName(tls->version()) : tls ? "TLS" : "TCP";
        exchange.host = tls && !tls->serverName().empty() ? tls->serverName() : tunnelHost;
        return exchange;
    }
    void emit(HttpExchange exchange)
    {
        emitted = true;
        owner.emit(std::move(exchange));
    }
};

class HttpParser
{
public:
    virtual ~HttpParser() = default;
    virtual bool feed(int direction, Bytes bytes, int64_t timestampUs) = 0;
    virtual void finish(int64_t timestampUs, bool graceful, std::string_view note) = 0;
    virtual size_t memory() const = 0;
};

namespace HttpSpyDetail
{
constexpr size_t MaximumHead = 65536, MaximumFrame = 1 << 20, MaximumStreams = 256, MaximumPipeline = 128;
constexpr std::string_view Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

std::string lowered(std::string_view value)
{
    std::string result(value);
    for (auto& c : result)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return result;
}

std::string_view trimmed(std::string_view value)
{
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
        value.remove_suffix(1);
    return value;
}

void addHeader(std::string& text, std::string_view name, std::string_view value, const HttpSpyOptions& options)
{
    text.append(name).append(": ");
    if (!options.credentials && credentialHeader(lowered(name)))
        text.append("[redacted, " + std::to_string(value.size()) + " characters]");
    else
        text.append(value);
    text.append("\r\n");
}

void addBody(std::vector<uint8_t>& body, uint64_t& total, Bytes bytes, size_t limit)
{
    total += bytes.size();
    if (body.size() < limit)
        body.insert(body.end(), bytes.begin(), bytes.begin() + std::min(bytes.size(), limit - body.size()));
}

struct Field
{
    std::string_view name, value;
};

bool matches(std::string_view data, std::string_view token)
{
    return data.size() >= token.size() ? data.starts_with(token) : token.starts_with(data);
}

// Whether the start of a client stream is an HTTP request line or the HTTP/2 preface: 1 yes, 0 not yet, -1 no.
int requestStart(Bytes bytes)
{
    const std::string_view data(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    int result = -1;
    for (const std::string_view token : {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ",
        "TRACE ", "PRI * HTTP/2.0"})
        if (matches(data, token))
        {
            if (data.size() >= token.size())
                return 1;
            result = 0;
        }
    return result;
}

// HTTP/1.x with pipelining, chunked bodies, and connection-delimited responses.
class Http1Parser : public HttpParser
{
public:
    explicit Http1Parser(HttpContext& context) : context_(context), options_(context.owner.options()) {}
    bool feed(int direction, Bytes bytes, int64_t timestampUs) override;
    void finish(int64_t timestampUs, bool graceful, std::string_view note) override;
    size_t memory() const override
    {
        size_t result = sizeof(*this) + streams_[0].buffer.capacity() + streams_[1].buffer.capacity();
        for (const auto& item : pending_)
            result += item.exchange.memory();
        return result;
    }

private:
    struct Pending
    {
        HttpExchange exchange;
        bool head{}, connect{}, requestDone{}, responseStarted{};
    };
    struct Stream
    {
        enum class Phase : uint8_t { Head, Length, ChunkSize, ChunkData, ChunkEnd, Trailer, Close } phase{};
        std::string buffer;
        uint64_t remaining{};
    };
    bool head(int direction, std::string text, int64_t timestampUs);
    bool request(std::string_view line, const std::vector<Field>& fields, const std::string& headers,
        int64_t timestampUs);
    bool response(std::string_view line, const std::vector<Field>& fields, const std::string& headers,
        int64_t timestampUs);
    void body(int direction, Bytes bytes);
    void end(int direction, int64_t timestampUs);
    HttpContext& context_;
    const HttpSpyOptions& options_;
    Stream streams_[2];
    std::deque<Pending> pending_;
    Pending* requesting_{};
    bool stopped_{};
    bool chunked_{}, hasLength_{};
    uint64_t length_{};
};

bool Http1Parser::feed(int direction, Bytes bytes, int64_t timestampUs)
{
    using Phase = Stream::Phase;
    auto& stream = streams_[direction];
    while (!bytes.empty() && !stopped_)
    {
        switch (stream.phase)
        {
        case Phase::Head:
        {
            const auto old = stream.buffer.size();
            stream.buffer.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            const auto terminator = stream.buffer.find("\r\n\r\n", old >= 3 ? old - 3 : 0);
            if (terminator == std::string::npos)
            {
                if (stream.buffer.size() > MaximumHead)
                    return false;
                bytes = {};
                break;
            }
            bytes = bytes.subspan(terminator + 4 - old);
            stream.buffer.resize(terminator);
            auto text = std::move(stream.buffer);
            stream.buffer.clear();
            if (!head(direction, std::move(text), timestampUs))
                return false;
            break;
        }
        case Phase::Length:
        case Phase::ChunkData:
        case Phase::Close:
        {
            const auto take = stream.phase == Phase::Close ? bytes.size() :
                static_cast<size_t>(std::min<uint64_t>(stream.remaining, bytes.size()));
            body(direction, bytes.first(take));
            bytes = bytes.subspan(take);
            if (stream.phase == Phase::Close)
                break;
            stream.remaining -= take;
            if (!stream.remaining)
            {
                if (stream.phase == Phase::Length)
                    end(direction, timestampUs);
                else
                {
                    stream.phase = Phase::ChunkEnd;
                    stream.remaining = 2;
                }
            }
            break;
        }
        case Phase::ChunkEnd:
        {
            const auto skip = static_cast<size_t>(std::min<uint64_t>(stream.remaining, bytes.size()));
            bytes = bytes.subspan(skip);
            stream.remaining -= skip;
            if (!stream.remaining)
                stream.phase = Phase::ChunkSize;
            break;
        }
        case Phase::ChunkSize:
        case Phase::Trailer:
        {
            const auto* newline = static_cast<const uint8_t*>(std::memchr(bytes.data(), '\n', bytes.size()));
            const auto count = newline ? static_cast<size_t>(newline - bytes.data()) : bytes.size();
            stream.buffer.append(reinterpret_cast<const char*>(bytes.data()), count);
            bytes = bytes.subspan(count + (newline ? 1 : 0));
            if (!newline)
            {
                if (stream.buffer.size() > MaximumHead)
                    return false;
                break;
            }
            const auto line = trimmed(stream.buffer);
            if (stream.phase == Phase::Trailer)
            {
                stream.buffer.clear();
                if (line.empty())
                    end(direction, timestampUs);
                break;
            }
            uint64_t size = 0;
            const auto digits = line.substr(0, line.find(';'));
            const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), size, 16);
            if (parsed.ec != std::errc{} || parsed.ptr == digits.data())
                return false;
            stream.buffer.clear();
            stream.remaining = size;
            stream.phase = size ? Phase::ChunkData : Phase::Trailer;
            break;
        }
        }
    }
    return true;
}

bool Http1Parser::head(int direction, std::string text, int64_t timestampUs)
{
    auto view = std::string_view(text);
    while (!view.empty() && (view.front() == '\r' || view.front() == '\n'))
        view.remove_prefix(1);
    if (view.empty())
        return true;
    const auto first = view.find("\r\n");
    const auto line = view.substr(0, first);
    auto rest = first == std::string_view::npos ? std::string_view{} : view.substr(first + 2);
    std::vector<Field> fields;
    std::string headers;
    chunked_ = hasLength_ = false;
    length_ = 0;
    while (!rest.empty())
    {
        const auto end = rest.find("\r\n");
        const auto part = rest.substr(0, end);
        rest = end == std::string_view::npos ? std::string_view{} : rest.substr(end + 2);
        if (part.empty())
            continue;
        const auto colon = part.find(':');
        if (colon == std::string_view::npos || colon == 0)
            return false;
        const Field field{trimmed(part.substr(0, colon)), trimmed(part.substr(colon + 1))};
        fields.push_back(field);
        addHeader(headers, field.name, field.value, options_);
        const auto name = lowered(field.name);
        if (name == "content-length")
        {
            const auto parsed = std::from_chars(field.value.data(), field.value.data() + field.value.size(), length_);
            if (parsed.ec != std::errc{})
                return false;
            hasLength_ = true;
        }
        else if (name == "transfer-encoding" && lowered(field.value).find("chunked") != std::string::npos)
            chunked_ = true;
    }
    return direction == 0 ? request(line, fields, headers, timestampUs) :
        response(line, fields, headers, timestampUs);
}

bool Http1Parser::request(std::string_view line, const std::vector<Field>& fields, const std::string& headers,
    int64_t timestampUs)
{
    const auto first = line.find(' '), last = line.rfind(' ');
    if (first == std::string_view::npos || last <= first || !line.substr(last + 1).starts_with("HTTP/1."))
        return false;
    if (pending_.size() >= MaximumPipeline)
        return false;
    Pending item;
    auto& exchange = item.exchange;
    exchange = context_.create(timestampUs);
    exchange.sequence = context_.sequence++;
    exchange.version = std::string(line.substr(last + 1));
    exchange.method = std::string(line.substr(0, first));
    exchange.target = std::string(trimmed(line.substr(first + 1, last - first - 1)));
    exchange.requestHeaders = headers;
    for (const auto& field : fields)
        if (lowered(field.name) == "host")
            exchange.host = std::string(field.value);
    item.head = exchange.method == "HEAD";
    item.connect = exchange.method == "CONNECT";
    if (item.connect)
        exchange.host = exchange.target;
    pending_.push_back(std::move(item));
    requesting_ = &pending_.back();
    auto& stream = streams_[0];
    if (chunked_)
        stream.phase = Stream::Phase::ChunkSize;
    else if (hasLength_ && length_)
    {
        stream.phase = Stream::Phase::Length;
        stream.remaining = length_;
    }
    else
        end(0, timestampUs);
    return true;
}

bool Http1Parser::response(std::string_view line, const std::vector<Field>& fields, const std::string& headers,
    int64_t timestampUs)
{
    int status = 0;
    if (!line.starts_with("HTTP/1.") || line.size() < 12 || line[8] != ' ' ||
        std::from_chars(line.data() + 9, line.data() + 12, status).ec != std::errc{})
        return false;

    // Interim responses precede the final one for the same request.
    if (status >= 100 && status < 200 && status != 101)
        return true;
    if (pending_.empty())
        return false;
    auto& item = pending_.front();
    auto& exchange = item.exchange;
    exchange.status = status;
    exchange.reason = line.size() > 13 ? std::string(trimmed(line.substr(13))) : std::string{};
    exchange.responseHeaders = headers;
    exchange.responseStartUs = timestampUs;
    item.responseStarted = true;
    std::string upgrade;
    for (const auto& field : fields)
    {
        const auto name = lowered(field.name);
        if (name == "content-type")
            exchange.contentType = std::string(field.value.substr(0, 256));
        else if (name == "upgrade")
            upgrade = std::string(field.value);
    }
    auto& stream = streams_[1];
    if (status == 101 || (item.connect && status >= 200 && status < 300))
    {
        exchange.note = status == 101 ? "Switched protocols" + (upgrade.empty() ? "" : " to " + upgrade) :
            "Tunnel established";
        stopped_ = true;
        if (item.connect)
        {
            context_.tunnel = true;
            context_.tunnelHost = exchange.target;
        }
        end(1, timestampUs);
        return true;
    }
    if (item.head || status == 204 || status == 304)
        end(1, timestampUs);
    else if (chunked_)
        stream.phase = Stream::Phase::ChunkSize;
    else if (hasLength_)
    {
        if (length_)
        {
            stream.phase = Stream::Phase::Length;
            stream.remaining = length_;
        }
        else
            end(1, timestampUs);
    }
    else
        stream.phase = Stream::Phase::Close;
    return true;
}

void Http1Parser::body(int direction, Bytes bytes)
{
    auto* item = direction == 0 ? requesting_ : pending_.empty() ? nullptr : &pending_.front();
    if (!item)
        return;
    if (direction == 0)
        addBody(item->exchange.requestBody, item->exchange.requestBytes, bytes, options_.bodyBytes);
    else
        addBody(item->exchange.responseBody, item->exchange.responseBytes, bytes, options_.bodyBytes);
}

void Http1Parser::end(int direction, int64_t timestampUs)
{
    streams_[direction].phase = Stream::Phase::Head;
    if (direction == 0)
    {
        if (!requesting_)
            return;
        requesting_->exchange.requestEndUs = timestampUs;
        requesting_->requestDone = true;
        if (!requesting_->responseStarted)
        {
            auto snapshot = requesting_->exchange;
            snapshot.state = "pending";
            context_.emit(std::move(snapshot));
        }
        requesting_ = nullptr;
        return;
    }
    if (pending_.empty())
        return;
    auto& item = pending_.front();
    item.exchange.endedUs = timestampUs;
    item.exchange.state = item.requestDone ? "complete" : "partial";
    if (!item.requestDone && item.exchange.note.empty())
        item.exchange.note = "The response ended before the request was complete.";
    if (requesting_ == &item)
        requesting_ = nullptr;
    context_.emit(std::move(item.exchange));
    pending_.pop_front();
}

void Http1Parser::finish(int64_t timestampUs, bool graceful, std::string_view note)
{
    // A response without a length is complete when the server closes the connection.
    if (graceful && streams_[1].phase == Stream::Phase::Close && !pending_.empty())
        end(1, timestampUs);
    for (auto& item : pending_)
    {
        item.exchange.endedUs = timestampUs;
        item.exchange.state = "partial";
        item.exchange.note = !note.empty() ? std::string(note) : item.responseStarted ?
            "The connection ended before the response was complete." : "No response was observed.";
        context_.emit(std::move(item.exchange));
    }
    pending_.clear();
    requesting_ = nullptr;
}

// HTTP/2 frames from both directions, with HPACK state kept per direction.
class Http2Parser : public HttpParser
{
public:
    explicit Http2Parser(HttpContext& context) : context_(context), options_(context.owner.options())
    {
        for (auto& direction : directions_)
        {
            nghttp2_hd_inflater* inflater = nullptr;
            if (nghttp2_hd_inflate_new(&inflater) != 0)
                throw std::runtime_error("HTTP/2 header decoding could not start");
            direction.inflater.reset(inflater);
            if (nghttp2_hd_inflate_change_table_size(inflater, 262144) != 0)
                throw std::runtime_error("HTTP/2 header decoding could not start");
        }
    }
    bool feed(int direction, Bytes bytes, int64_t timestampUs) override;
    void finish(int64_t timestampUs, bool graceful, std::string_view note) override;
    size_t memory() const override
    {
        size_t result = sizeof(*this);
        for (const auto& direction : directions_)
            result += direction.buffer.capacity() + direction.block.capacity() + 16384;
        for (const auto& [id, stream] : streams_)
            result += stream.exchange.memory() + 64;
        return result;
    }

private:
    struct Direction
    {
        std::vector<uint8_t> buffer, block;
        std::unique_ptr<nghttp2_hd_inflater, decltype(&nghttp2_hd_inflate_del)> inflater{
            nullptr, nghttp2_hd_inflate_del};
        uint32_t blockStream{};
        uint8_t blockFlags{};
        bool prefaceSeen{}, continuing{}, promise{};
    };
    struct Stream
    {
        HttpExchange exchange;
        bool requestDone{}, responseStarted{};
    };
    bool frame(int direction, uint8_t type, uint8_t flags, uint32_t stream, Bytes payload, int64_t timestampUs);
    bool headers(int direction, int64_t timestampUs);
    void end(int direction, uint32_t id, int64_t timestampUs);
    HttpContext& context_;
    const HttpSpyOptions& options_;
    Direction directions_[2];
    std::map<uint32_t, Stream> streams_;
};

bool Http2Parser::feed(int direction, Bytes bytes, int64_t timestampUs)
{
    auto& side = directions_[direction];
    side.buffer.insert(side.buffer.end(), bytes.begin(), bytes.end());
    size_t offset = 0;
    if (direction == 0 && !side.prefaceSeen)
    {
        const std::string_view data(reinterpret_cast<const char*>(side.buffer.data()), side.buffer.size());
        if (!matches(data, Preface))
            return false;
        if (data.size() < Preface.size())
            return true;
        side.prefaceSeen = true;
        offset = Preface.size();
    }
    while (side.buffer.size() - offset >= 9)
    {
        const Bytes header(side.buffer.data() + offset, 9);
        const size_t length = (size_t{header[0]} << 16) | (size_t{header[1]} << 8) | header[2];
        if (length > MaximumFrame)
            return false;
        if (side.buffer.size() - offset < 9 + length)
            break;
        const auto stream = be32(header, 5) & 0x7fffffff;
        if (!frame(direction, header[3], header[4], stream, Bytes(side.buffer.data() + offset + 9, length),
            timestampUs))
            return false;
        offset += 9 + length;
    }
    side.buffer.erase(side.buffer.begin(), side.buffer.begin() + static_cast<ptrdiff_t>(offset));
    return true;
}

bool Http2Parser::frame(int direction, uint8_t type, uint8_t flags, uint32_t stream, Bytes payload,
    int64_t timestampUs)
{
    auto& side = directions_[direction];
    if (side.continuing && (type != 9 || stream != side.blockStream))
        return false;

    // Padding and priority fields precede the content of DATA, HEADERS, and PUSH_PROMISE frames.
    if ((type == 0 || type == 1 || type == 5) && (flags & 8))
    {
        if (payload.empty() || payload[0] >= payload.size())
            return false;
        payload = payload.subspan(1, payload.size() - 1 - payload[0]);
    }
    if (type == 1 && (flags & 0x20))
    {
        if (payload.size() < 5)
            return false;
        payload = payload.subspan(5);
    }
    if (type == 5)
    {
        if (direction != 1 || payload.size() < 4)
            return false;
        payload = payload.subspan(4);
    }
    switch (type)
    {
    case 0:
        if (!stream)
            return false;
        if (const auto found = streams_.find(stream); found != streams_.end())
        {
            auto& exchange = found->second.exchange;
            if (direction == 0)
                addBody(exchange.requestBody, exchange.requestBytes, payload, options_.bodyBytes);
            else
                addBody(exchange.responseBody, exchange.responseBytes, payload, options_.bodyBytes);
            if (flags & 1)
                end(direction, stream, timestampUs);
        }
        return true;
    case 1:
    case 5:
    case 9:
        if (!stream || (type == 9 && !side.continuing))
            return false;
        if (type != 9)
        {
            side.block.clear();
            side.blockStream = stream;
            side.blockFlags = flags;
            side.promise = type == 5;
        }
        if (payload.size() > 262144 - side.block.size())
            return false;
        side.block.insert(side.block.end(), payload.begin(), payload.end());
        side.continuing = !(flags & 4);
        return side.continuing || headers(direction, timestampUs);
    case 3:
        if (const auto found = streams_.find(stream); found != streams_.end())
        {
            auto& exchange = found->second.exchange;
            exchange.endedUs = timestampUs;
            exchange.state = "partial";
            exchange.note = "The stream was reset" + (payload.size() == 4 ?
                " (error " + std::to_string(be32(payload, 0)) + ")" : std::string{}) + ".";
            context_.emit(std::move(exchange));
            streams_.erase(found);
        }
        return true;
    default:
        return true;
    }
}

bool Http2Parser::headers(int direction, int64_t timestampUs)
{
    auto& side = directions_[direction];
    std::vector<std::pair<std::string, std::string>> fields;
    size_t consumed = 0, total = 0;
    for (;;)
    {
        nghttp2_nv field{};
        int flags = 0;
        const auto size = nghttp2_hd_inflate_hd3(side.inflater.get(), &field, &flags,
            side.block.empty() ? nullptr : side.block.data() + consumed, side.block.size() - consumed, 1);
        if (size < 0)
            return false;
        consumed += static_cast<size_t>(size);
        if (flags & NGHTTP2_HD_INFLATE_EMIT)
        {
            total += field.namelen + field.valuelen;
            if (fields.size() >= 512 || total > 262144)
                return false;
            fields.emplace_back(std::string(reinterpret_cast<const char*>(field.name), field.namelen),
                std::string(reinterpret_cast<const char*>(field.value), field.valuelen));
        }
        if (flags & NGHTTP2_HD_INFLATE_FINAL)
            break;
        if (!size && !(flags & NGHTTP2_HD_INFLATE_EMIT))
            return false;
    }
    nghttp2_hd_inflate_end_headers(side.inflater.get());
    side.block.clear();
    if (side.promise)
        return true;
    const auto id = side.blockStream;
    const bool last = (side.blockFlags & 1) != 0;
    std::string text, method, scheme, authority, path;
    int status = 0;
    std::string contentType;
    for (const auto& [name, value] : fields)
    {
        if (name.starts_with(':'))
        {
            if (name == ":method") method = value;
            else if (name == ":scheme") scheme = value;
            else if (name == ":authority") authority = value;
            else if (name == ":path") path = value;
            else if (name == ":status") std::from_chars(value.data(), value.data() + value.size(), status);
            continue;
        }
        addHeader(text, name, value, options_);
        if (name == "content-type")
            contentType = value.substr(0, 256);
    }
    auto found = streams_.find(id);
    if (direction == 0)
    {
        if (found == streams_.end())
        {
            if ((id & 1) == 0 || method.empty() || streams_.size() >= MaximumStreams)
                return false;
            Stream stream;
            auto& exchange = stream.exchange;
            exchange = context_.create(timestampUs);
            exchange.sequence = context_.sequence++;
            exchange.version = "HTTP/2";
            exchange.method = method;
            exchange.target = path.empty() ? authority : path;
            if (!authority.empty())
                exchange.host = authority;
            if (!scheme.empty())
                exchange.scheme = scheme;
            exchange.requestHeaders = text;
            found = streams_.emplace(id, std::move(stream)).first;
        }
        else
            found->second.exchange.requestHeaders += text;
    }
    else
    {
        if (found == streams_.end() || (status >= 100 && status < 200))
            return true;
        auto& stream = found->second;
        if (!stream.responseStarted)
        {
            stream.responseStarted = true;
            stream.exchange.status = status;
            stream.exchange.responseStartUs = timestampUs;
            stream.exchange.responseHeaders = text;
            stream.exchange.contentType = contentType;
        }
        else
            stream.exchange.responseHeaders += text;
    }
    if (last)
        end(direction, id, timestampUs);
    return true;
}

void Http2Parser::end(int direction, uint32_t id, int64_t timestampUs)
{
    const auto found = streams_.find(id);
    if (found == streams_.end())
        return;
    auto& stream = found->second;
    if (direction == 0)
    {
        stream.exchange.requestEndUs = timestampUs;
        stream.requestDone = true;
        if (!stream.responseStarted)
        {
            auto snapshot = stream.exchange;
            snapshot.state = "pending";
            context_.emit(std::move(snapshot));
        }
        return;
    }
    stream.exchange.endedUs = timestampUs;
    stream.exchange.state = "complete";
    context_.emit(std::move(stream.exchange));
    streams_.erase(found);
}

void Http2Parser::finish(int64_t timestampUs, bool, std::string_view note)
{
    for (auto& [id, stream] : streams_)
    {
        stream.exchange.endedUs = timestampUs;
        stream.exchange.state = "partial";
        stream.exchange.note = !note.empty() ? std::string(note) : stream.responseStarted ?
            "The connection ended before the response was complete." : "No response was observed.";
        context_.emit(std::move(stream.exchange));
    }
    streams_.clear();
}
}
using namespace HttpSpyDetail;

void HttpSpy::emit(HttpExchange exchange)
{
    // A request is reported as pending before its response arrives; only settled states are counted.
    if (exchange.state != "pending")
        ++exchanges;
    if (sink_)
        sink_(std::move(exchange));
}

std::unique_ptr<HttpSpyFlow> HttpSpy::open(const FlowKey& key, uint64_t flowId, int64_t startedUs)
{
    return std::make_unique<HttpSpyFlow>(*this, key, flowId, startedUs);
}

HttpSpyFlow::HttpSpyFlow(HttpSpy& owner, const FlowKey& key, uint64_t flowId, int64_t startedUs) :
    owner_(owner), key_(key), context_(std::make_unique<HttpContext>(HttpContext{owner, flowId, startedUs})),
    lastUs_(startedUs) {}

HttpSpyFlow::~HttpSpyFlow() = default;

bool HttpSpyFlow::active() const { return phase_ != Phase::Done; }
bool HttpSpyFlow::waiting() const { return tls_ && tls_->waiting(); }

size_t HttpSpyFlow::memory() const
{
    return sizeof(*this) + sizeof(HttpContext) + streams_[0].memory() + streams_[1].memory() + sniffed_.capacity() +
        plainSniffed_.capacity() + early_.capacity() + (tls_ ? tls_->memory() : 0) + (http_ ? http_->memory() : 0);
}

bool HttpSpyFlow::feed(const TransportPacket& packet, int64_t timestampUs, size_t budget)
{
    if (phase_ == Phase::Done)
        return false;
    const int direction = packet.source == key_.a ? 0 : 1;
    const bool syn = (packet.flags & 2) != 0;
    lastUs_ = std::max(lastUs_, timestampUs);
    if (syn)
    {
        streams_[direction].begin(packet.sequence + 1);
        if (client_ < 0)
            client_ = (packet.flags & 16) ? 1 - direction : direction;
    }
    if (!packet.payload.empty())
    {
        // A truncated segment leaves a hole that no later byte can fill.
        if (packet.truncated)
            conclude(timestampUs, "The capture truncated a large segment, so the rest of the connection could not "
                "be decoded.");
        else if (!streams_[direction].feed(packet.sequence + (syn ? 1 : 0), packet.payload,
            [&](Bytes bytes) { return consume(direction, bytes, timestampUs); }) && phase_ != Phase::Done)
            conclude(timestampUs, "The connection exceeded the reassembly limit or contradicted itself.");
    }
    if (phase_ != Phase::Done && memory() > budget)
        conclude(timestampUs, "The inspection memory budget was reached.");
    if (phase_ == Phase::Done)
    {
        tls_.reset();
        http_.reset();
        sniffed_ = plainSniffed_ = early_ = {};
        return false;
    }
    return true;
}

void HttpSpyFlow::tick(int64_t)
{
    if (phase_ != Phase::Tls || !tls_ || !tls_->waiting())
        return;
    tls_->retry([&](int direction, Bytes bytes, int64_t atUs) { plain(direction, bytes, atUs); });
    if (tls_->finished())
        conclude(tls_->timestampUs(), tls_->reason());
    if (phase_ == Phase::Done)
    {
        tls_.reset();
        http_.reset();
    }
}

void HttpSpyFlow::finish(int64_t timestampUs, std::string_view reason)
{
    tick(timestampUs);
    if (phase_ == Phase::Done)
        return;
    auto note = streams_[0].pending() || streams_[1].pending() ?
        "A packet was missed, so the rest of the connection could not be decoded." : std::string{};
    conclude(timestampUs, std::move(note), reason == "TCP close observed");
    tls_.reset();
    http_.reset();
    sniffed_ = plainSniffed_ = early_ = {};
}

bool HttpSpyFlow::consume(int direction, Bytes bytes, int64_t timestampUs)
{
    if (phase_ == Phase::Sniff)
        return sniff(direction, bytes, timestampUs);
    if (phase_ == Phase::Plain)
        return plain(direction == client_ ? 0 : 1, bytes, timestampUs);
    if (phase_ != Phase::Tls)
        return false;
    // An application's burst can fill the ciphertext queue before the collector's next periodic key-log poll.
    if (tls_->waiting())
        owner_.refreshKeys();
    tls_->feed(direction == client_ ? 0 : 1, bytes, timestampUs,
        [&](int side, Bytes data, int64_t atUs) { plain(side, data, atUs); });
    if (tls_->finished())
        conclude(tls_->timestampUs(), tls_->reason());
    return phase_ != Phase::Done;
}

bool HttpSpyFlow::sniff(int direction, Bytes bytes, int64_t timestampUs)
{
    auto abandon = [&]
    {
        phase_ = Phase::Done;
        return false;
    };
    if (client_ < 0)
        client_ = direction;

    // Only a client that speaks first can open a TLS or HTTP connection.
    if (direction != client_)
        return abandon();
    sniffed_.insert(sniffed_.end(), bytes.begin(), bytes.end());
    context_->client = client_ == 0 ? key_.a : key_.b;
    context_->server = client_ == 0 ? key_.b : key_.a;
    if (sniffed_.size() >= 3 && sniffed_[0] == 0x16 && sniffed_[1] == 3 && sniffed_[2] <= 4)
    {
        if (sniffed_.size() < 6)
            return true;
        if (sniffed_[5] != 1)
            return abandon();
        phase_ = Phase::Tls;
        tls_ = std::make_unique<TlsDecryptor>(owner_.keys(), owner_.options().queueBytes);
        context_->tls = tls_.get();
        ++owner_.tlsFlows;
        const auto data = std::move(sniffed_);
        sniffed_.clear();
        return consume(direction, data, timestampUs);
    }
    const auto start = requestStart(sniffed_);
    if (start < 0)
        return abandon();
    if (start == 0)
        return true;
    phase_ = Phase::Plain;
    const auto data = std::move(sniffed_);
    sniffed_.clear();
    return plain(0, data, timestampUs);
}

bool HttpSpyFlow::plain(int direction, Bytes bytes, int64_t timestampUs)
{
    if (phase_ == Phase::Done)
        return false;
    if (!http_)
    {
        // A server may speak first inside TLS, so hold its bytes until the client's protocol is known.
        if (direction == 1)
        {
            early_.insert(early_.end(), bytes.begin(), bytes.end());
            if (early_.size() > MaximumHead)
                conclude(timestampUs, "The server sent unexpected data before the first request.");
            return phase_ != Phase::Done;
        }
        plainSniffed_.insert(plainSniffed_.end(), bytes.begin(), bytes.end());
        const auto start = requestStart(plainSniffed_);
        if (start == 0)
            return true;
        if (start < 0)
        {
            conclude(timestampUs, "The decrypted stream is not HTTP.");
            return false;
        }
        if (plainSniffed_.size() >= 14 && std::memcmp(plainSniffed_.data(), "PRI * HTTP/2.0", 14) == 0)
            http_ = std::make_unique<Http2Parser>(*context_);
        else
            http_ = std::make_unique<Http1Parser>(*context_);
        const auto first = std::move(plainSniffed_);
        plainSniffed_.clear();
        auto ok = http_->feed(0, first, timestampUs);
        if (ok && !early_.empty())
        {
            const auto held = std::move(early_);
            early_.clear();
            ok = http_->feed(1, held, timestampUs);
        }
        if (!ok)
        {
            conclude(timestampUs, "The HTTP stream could not be decoded.");
            return false;
        }
        return true;
    }
    if (!http_->feed(direction, bytes, timestampUs))
    {
        conclude(timestampUs, "The HTTP stream could not be decoded.");
        return false;
    }

    // Once a proxy accepts CONNECT, the connection carries a new protocol from the client's next byte.
    if (context_->tunnel)
    {
        http_->finish(timestampUs, true, {});
        http_.reset();
        tls_.reset();
        context_->tls = nullptr;
        context_->tunnel = false;
        sniffed_.clear();
        plainSniffed_.clear();
        early_.clear();
        phase_ = Phase::Sniff;
    }
    return true;
}

void HttpSpyFlow::conclude(int64_t timestampUs, std::string note, bool graceful)
{
    if (phase_ == Phase::Done)
        return;
    phase_ = Phase::Done;
    if (http_)
        http_->finish(timestampUs, graceful, note);
    if (!tls_)
        return;
    if (context_->emitted)
        ++owner_.decoded;
    if (tls_->state() == TlsDecryptor::State::Unsupported)
        ++owner_.unsupported;
    else if (tls_->state() == TlsDecryptor::State::Failed)
        ++owner_.failed;
    else if (tls_->waiting() && !context_->emitted)
        ++owner_.withoutSecrets;
    if (context_->emitted)
        return;

    // Report a connection that carried TLS but produced no messages, with the reason.
    if (note.empty())
        note = tls_->reason();
    if (note.empty())
        note = "The connection closed before an HTTP request was decoded.";
    auto exchange = context_->create(context_->startedUs);
    exchange.state = "encrypted";
    exchange.note = std::move(note);
    exchange.endedUs = timestampUs;
    owner_.emit(std::move(exchange));
}
}
