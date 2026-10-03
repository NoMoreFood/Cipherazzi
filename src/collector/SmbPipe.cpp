#include "SmbPipe.h"
#include "Rpc.h"
#include <algorithm>

namespace Cipherazzi
{
static constexpr size_t MaxTrees = 32, MaxPending = 64, MaxPipes = 64, MaxRpcBytes = 256 * 1024;

static uint16_t value16(Bytes bytes, size_t offset)
{
    return uint16_t(bytes[offset]) | uint16_t(bytes[offset + 1]) << 8;
}

static uint32_t value32(Bytes bytes, size_t offset)
{
    return uint32_t(bytes[offset]) | uint32_t(bytes[offset + 1]) << 8 |
        uint32_t(bytes[offset + 2]) << 16 | uint32_t(bytes[offset + 3]) << 24;
}

static uint64_t value64(Bytes bytes, size_t offset)
{
    return uint64_t(value32(bytes, offset)) | uint64_t(value32(bytes, offset + 4)) << 32;
}

static Bytes content(Bytes message, size_t offset, size_t length, size_t minimum)
{
    return length && offset >= minimum && offset <= message.size() && length <= message.size() - offset ?
        message.subspan(offset, length) : Bytes{};
}

static std::array<uint8_t, 16> fileId(Bytes message, size_t offset)
{
    std::array<uint8_t, 16> result{};
    std::copy_n(message.begin() + offset, result.size(), result.begin());
    return result;
}

size_t SmbPipeInspection::memory() const
{
    size_t result = trees_.capacity() * sizeof(Tree) + pending_.capacity() * sizeof(Pending) +
        pipes_.capacity() * sizeof(Pipe) + legacyTrees_.capacity() * sizeof(LegacyTree) +
        legacyPending_.capacity() * sizeof(LegacyPending);
    for (const auto& pipe : pipes_)
        for (const auto& rpc : pipe.rpc)
            result += rpc.capacity();
    return result;
}

SmbPipeInspection::Pipe* SmbPipeInspection::pipe(uint64_t session, uint32_t tree, Bytes file)
{
    if (file.size() != 16)
        return nullptr;
    const auto found = std::find_if(pipes_.begin(), pipes_.end(), [&](const Pipe& item)
    {
        return !item.legacy && item.session == session && item.tree == tree &&
            std::equal(item.file.begin(), item.file.end(), file.begin());
    });
    return found == pipes_.end() ? nullptr : &*found;
}

SmbPipeInspection::Pipe* SmbPipeInspection::legacyPipe(uint16_t user, uint16_t tree, uint16_t file)
{
    const auto found = std::find_if(pipes_.begin(), pipes_.end(), [&](const Pipe& item)
    {
        return item.legacy && item.session == user && item.tree == tree &&
            (uint16_t(item.file[0]) | uint16_t(item.file[1]) << 8) == file;
    });
    return found == pipes_.end() ? nullptr : &*found;
}

void SmbPipeInspection::forgetPending(const Pipe& pipe)
{
    if (pipe.legacy)
    {
        const uint16_t fid = uint16_t(pipe.file[0]) | uint16_t(pipe.file[1]) << 8;
        std::erase_if(legacyPending_, [&](const LegacyPending& item)
        {
            return item.user == pipe.session && item.tree == pipe.tree && item.file == fid &&
                (item.command == 0x2e || item.command == 0x25);
        });
    }
    else
        std::erase_if(pending_, [&](const Pending& item)
        {
            return item.session == pipe.session && item.tree == pipe.tree && item.file == pipe.file &&
                (item.command == 8 || item.command == 11);
        });
}

void SmbPipeInspection::recountRpcBytes()
{
    rpcBytes_ = 0;
    for (const auto& pipe : pipes_)
        for (const auto& rpc : pipe.rpc)
            rpcBytes_ += rpc.size();
}

void SmbPipeInspection::append(Pipe& pipe, int direction, Bytes bytes, nlohmann::json& fields)
{
    // A damaged or oversized pipe stream cannot be resynchronized without risking an invented bind.
    if (direction < 0 || direction > 1 || pipe.disabled[direction] || bytes.empty())
        return;
    auto& rpc = pipe.rpc[direction];
    if (bytes.size() > MaxRpcBytes - rpcBytes_)
    {
        rpcBytes_ -= rpc.size();
        std::vector<uint8_t>().swap(rpc);
        pipe.disabled[direction] = true;
        return;
    }
    rpc.insert(rpc.end(), bytes.begin(), bytes.end());
    rpcBytes_ += bytes.size();
    while (rpc.size() >= 16)
    {
        if (rpc[0] != 5 || rpc[1] != 0 || (rpc[4] != 0x10 && rpc[4] != 0))
            break;
        const size_t length = rpc[4] == 0x10 ? value16(rpc, 8) :
            size_t(rpc[8]) << 8 | rpc[9];
        if (length < 16)
            break;
        if (rpc.size() < length)
            return;
        nlohmann::json parsed;
        if (!parseRpcBind(Bytes(rpc).first(length), parsed))
            break;
        if (parsed.contains("rpc_bind"))
        {
            auto bind = std::move(parsed["rpc_bind"]);
            bind["transport"] = "SMB named pipe";
            if (!fields.contains("rpc_bind_events"))
                fields["rpc_bind_events"] = nlohmann::json::array();
            if (fields["rpc_bind_events"].size() < 64)
                fields["rpc_bind_events"].push_back(std::move(bind));
            else
                fields["rpc_bind_events_dropped"] = fields.value("rpc_bind_events_dropped", 0) + 1;
            fields["smb_named_pipe_rpc_observed"] = true;
        }
        rpc.erase(rpc.begin(), rpc.begin() + length);
        rpcBytes_ -= length;
    }
    if (rpc.size() < 16)
        return;
    rpcBytes_ -= rpc.size();
    std::vector<uint8_t>().swap(rpc);
    pipe.disabled[direction] = true;
}

void SmbPipeInspection::feed(Bytes message, int direction, nlohmann::json& fields)
{
    if (message.size() >= 4 && message[0] == 0xff && message[1] == 'S' &&
        message[2] == 'M' && message[3] == 'B')
    {
        feedLegacy(message, direction, fields);
        return;
    }

    // Every command in a compound has its own SMB2 header, and offsets are relative to that header.
    for (size_t count = 0; count < 64 && message.size() >= 64; ++count)
    {
        if (message[0] != 0xfe || message[1] != 'S' || message[2] != 'M' || message[3] != 'B' ||
            value16(message, 4) != 64)
            return;
        const size_t next = value32(message, 20);
        if (next && (next < 64 || next % 8 || next >= message.size()))
            return;
        const Bytes part = next ? message.first(next) : message;
        const uint16_t command = value16(part, 12);
        const uint32_t flags = value32(part, 16);
        const bool response = (flags & 1) != 0, related = (flags & 4) != 0;
        const uint32_t status = response ? value32(part, 8) : 0;
        const uint64_t messageId = value64(part, 24), session = value64(part, 40);
        const uint32_t tree = value32(part, 36);

        // Related operations can inherit a previous header or an all-ones FileId, which is not resolved here.
        if (!related && session && direction >= 0 && direction <= 1)
        {
            if (!response)
            {
                if (command == 2 && part.size() >= 68 && value16(part, 64) == 4)
                {
                    std::erase_if(trees_, [&](const Tree& item) { return item.session == session; });
                    std::erase_if(pending_, [&](const Pending& item) { return item.session == session; });
                    std::erase_if(pipes_, [&](const Pipe& item) { return !item.legacy && item.session == session; });
                    rpcBytes_ = 0;
                    for (const auto& pipe : pipes_)
                        for (const auto& rpc : pipe.rpc)
                            rpcBytes_ += rpc.size();
                }
                else if (command == 4 && part.size() >= 68 && value16(part, 64) == 4)
                {
                    std::erase_if(trees_, [&](const Tree& item) { return item.session == session && item.id == tree; });
                    std::erase_if(
                        pending_, [&](const Pending& item) { return item.session == session && item.tree == tree; });
                    std::erase_if(pipes_,
                        [&](const Pipe& item) { return !item.legacy && item.session == session && item.tree == tree; });
                    rpcBytes_ = 0;
                    for (const auto& pipe : pipes_)
                        for (const auto& rpc : pipe.rpc)
                            rpcBytes_ += rpc.size();
                }
                else
                {
                    Pending pending{session, messageId, tree, {}, static_cast<uint8_t>(command), direction};
                    bool keep = false;
                    if (command == 3 && part.size() >= 72 && value16(part, 64) == 9)
                    {
                        const auto name = content(part, value16(part, 68), value16(part, 70), 72);
                        keep = !name.empty() && name.size() % 2 == 0;
                    }
                    else if (command == 5 && part.size() >= 120 && value16(part, 64) == 57)
                    {
                        const auto name = content(part, value16(part, 108), value16(part, 110), 120);
                        keep = !name.empty() && name.size() % 2 == 0 &&
                            std::any_of(trees_.begin(), trees_.end(),
                                [&](const Tree& item) { return item.session == session && item.id == tree; });
                    }
                    else if (command == 8 && part.size() >= 112 && value16(part, 64) == 49 &&
                        value32(part, 100) == 0 && pipe(session, tree, part.subspan(80, 16)))
                    {
                        pending.file = fileId(part, 80);
                        keep = true;
                    }
                    else if (command == 9 && part.size() >= 112 && value16(part, 64) == 49 &&
                        value32(part, 96) == 0)
                    {
                        if (auto* opened = pipe(session, tree, part.subspan(80, 16)))
                        {
                            const auto data = content(part, value16(part, 66), value32(part, 68), 112);
                            append(*opened, direction, data, fields);
                        }
                    }
                    else if (command == 11 && part.size() >= 120 && value16(part, 64) == 57 &&
                        value32(part, 68) == 0x0011c017)
                    {
                        if (auto* opened = pipe(session, tree, part.subspan(72, 16)))
                        {
                            const size_t size = value32(part, 92);
                            const auto data = content(part, value32(part, 88), size, 120);
                            if (!size || !data.empty())
                            {
                                append(*opened, direction, data, fields);
                                pending.file = fileId(part, 72);
                                keep = true;
                            }
                        }
                    }
                    else if (command == 6 && part.size() >= 88 && value16(part, 64) == 24)
                    {
                        const auto file = fileId(part, 72);
                        std::erase_if(pipes_,
                            [&](const Pipe& item)
                            {
                                return !item.legacy && item.session == session && item.tree == tree &&
                                    item.file == file;
                            });
                        std::erase_if(pending_, [&](const Pending& item)
                            { return item.session == session && item.tree == tree && item.file == file; });
                        rpcBytes_ = 0;
                        for (const auto& pipe : pipes_)
                            for (const auto& rpc : pipe.rpc)
                                rpcBytes_ += rpc.size();
                    }
                    if (keep)
                    {
                        std::erase_if(pending_, [&](const Pending& item)
                        {
                            return item.session == session && item.message == messageId &&
                                item.direction == direction;
                        });
                        if (pending_.size() == MaxPending)
                            pending_.erase(pending_.begin());
                        pending_.push_back(pending);
                    }
                }
            }
            else if (status != 0x00000103)
            {
                const auto matched = std::find_if(pending_.begin(), pending_.end(), [&](const Pending& item)
                {
                    return item.session == session && item.message == messageId && item.command == command &&
                        item.direction != direction;
                });
                if (matched != pending_.end())
                {
                    const Pending pending = *matched;
                    pending_.erase(matched);
                    if (status == 0 && command == 3 && tree && part.size() >= 80 &&
                        value16(part, 64) == 16)
                    {
                        std::erase_if(
                            trees_, [&](const Tree& item) { return item.session == session && item.id == tree; });
                        std::erase_if(pending_,
                            [&](const Pending& item) { return item.session == session && item.tree == tree; });
                        std::erase_if(pipes_, [&](const Pipe& item)
                            { return !item.legacy && item.session == session && item.tree == tree; });
                        recountRpcBytes();
                        if (part[66] == 2)
                        {
                            if (trees_.size() == MaxTrees)
                            {
                                const Tree oldest = trees_.front();
                                trees_.erase(trees_.begin());
                                std::erase_if(pending_, [&](const Pending& item)
                                    { return item.session == oldest.session && item.tree == oldest.id; });
                                std::erase_if(pipes_,
                                    [&](const Pipe& item)
                                    {
                                        return !item.legacy && item.session == oldest.session && item.tree == oldest.id;
                                    });
                                recountRpcBytes();
                            }
                            trees_.push_back({session, tree});
                        }
                    }
                    else if (status == 0 && command == 5 && part.size() >= 152 && value16(part, 64) == 89 &&
                        std::any_of(trees_.begin(), trees_.end(),
                            [&](const Tree& item) { return item.session == session && item.id == pending.tree; }))
                    {
                        const auto file = fileId(part, 128);
                        if (!std::all_of(file.begin(), file.end(), [](uint8_t byte) { return byte == 0xff; }))
                        {
                            if (auto* opened = pipe(session, pending.tree, file))
                                forgetPending(*opened);
                            std::erase_if(pipes_,
                                [&](const Pipe& item)
                                {
                                    return !item.legacy && item.session == session && item.tree == pending.tree &&
                                        item.file == file;
                                });
                            recountRpcBytes();
                            if (pipes_.size() == MaxPipes)
                            {
                                forgetPending(pipes_.front());
                                for (const auto& rpc : pipes_.front().rpc)
                                    rpcBytes_ -= rpc.size();
                                pipes_.erase(pipes_.begin());
                            }
                            pipes_.push_back({session, pending.tree, file});
                        }
                    }
                    else if (status == 0 && command == 8 && part.size() >= 80 && value16(part, 64) == 17 &&
                        value32(part, 76) == 0)
                    {
                        if (auto* opened = pipe(session, pending.tree, pending.file))
                        {
                            const auto data = content(part, part[66], value32(part, 68), 80);
                            append(*opened, direction, data, fields);
                        }
                    }
                    else if (status == 0 && command == 11 && part.size() >= 112 && value16(part, 64) == 49 &&
                        value32(part, 68) == 0x0011c017 &&
                        std::equal(pending.file.begin(), pending.file.end(), part.begin() + 72))
                    {
                        if (auto* opened = pipe(session, pending.tree, pending.file))
                        {
                            const auto data = content(part, value32(part, 96), value32(part, 100), 112);
                            append(*opened, direction, data, fields);
                        }
                    }
                }
            }
        }
        if (!next)
            return;
        message = message.subspan(next);
    }
}

void SmbPipeInspection::feedLegacy(Bytes message, int direction, nlohmann::json& fields)
{
    if (direction < 0 || direction > 1 || message.size() < 35)
        return;
    struct Part
    {
        uint8_t command{};
        Bytes words, data;
        size_t dataStart{};
    };

    // Chained SMB1 commands can change user or tree identity within one frame; inspect standalone commands only.
    const size_t wordBytes = size_t(message[32]) * 2;
    if (wordBytes > message.size() - 35)
        return;
    const size_t dataStart = 35 + wordBytes;
    const size_t dataLength = value16(message, 33 + wordBytes);
    if (dataLength != message.size() - dataStart)
        return;
    const Bytes words = message.subspan(33, wordBytes);
    const uint8_t command = message[4];
    const bool andx = command == 0x73 || command == 0x75 || command == 0xa2 ||
        command == 0x2d || command == 0x2e || command == 0x2f || command == 0x74;
    if (andx && (wordBytes < 4 || words[0] != 0xff))
        return;
    const Part parsed{command, words, message.subspan(dataStart, dataLength), dataStart};

    const bool response = (message[9] & 0x80) != 0;
    const uint32_t status = value32(message, 5);
    const uint32_t process = uint32_t(value16(message, 12)) << 16 | value16(message, 26);
    const uint16_t tree = value16(message, 24), user = value16(message, 28), mid = value16(message, 30);
    auto payload = [&](const Part& part, size_t dataOffset, size_t dataLength)
    {
        return dataLength && dataOffset >= part.dataStart && dataOffset <= part.dataStart + part.data.size() &&
            dataLength <= part.dataStart + part.data.size() - dataOffset ?
            message.subspan(dataOffset, dataLength) : Bytes{};
    };
    auto dropPipes = [&](auto predicate)
    {
        std::erase_if(pipes_, [&](const Pipe& item) { return item.legacy && predicate(item); });
        recountRpcBytes();
    };

    // Pair replies by process and multiplex ID, then scope handles to the returned user and tree IDs.
    const Part& part = parsed;
    if (!response)
    {
        if (part.command == 0x71 && part.words.empty())
        {
            std::erase_if(legacyTrees_, [&](const LegacyTree& item) { return item.user == user && item.id == tree; });
            std::erase_if(
                legacyPending_, [&](const LegacyPending& item) { return item.user == user && item.tree == tree; });
            dropPipes([&](const Pipe& item) { return item.session == user && item.tree == tree; });
            return;
        }
        if (part.command == 0x74 && part.words.size() == 4)
        {
            std::erase_if(legacyTrees_, [&](const LegacyTree& item) { return item.user == user; });
            std::erase_if(legacyPending_, [&](const LegacyPending& item) { return item.user == user; });
            dropPipes([&](const Pipe& item) { return item.session == user; });
            return;
        }
        if (part.command == 0x04 && part.words.size() == 6)
        {
            const uint16_t fid = value16(part.words, 0);
            std::erase_if(legacyPending_,
                [&](const LegacyPending& item) { return item.user == user && item.tree == tree && item.file == fid; });
            dropPipes([&](const Pipe& item)
            {
                return item.session == user && item.tree == tree &&
                    (uint16_t(item.file[0]) | uint16_t(item.file[1]) << 8) == fid;
            });
            return;
        }

        LegacyPending pending{process, user, tree, mid, 0, part.command, direction};
        bool keep = false;
        if (part.command == 0x75 && part.words.size() == 8)
        {
            pending.disconnectTree = (value16(part.words, 4) & 1) != 0;
            keep = value16(part.words, 6) <= part.data.size();
        }
        else if (part.command == 0xa2 && part.words.size() == 48 &&
            std::any_of(legacyTrees_.begin(), legacyTrees_.end(),
                [&](const LegacyTree& item) { return item.user == user && item.id == tree; }))
            keep = value16(part.words, 5) && value16(part.words, 5) <= part.data.size();
        else if (part.command == 0x2e && (part.words.size() == 20 || part.words.size() == 24))
        {
            pending.file = value16(part.words, 4);
            keep = legacyPipe(user, tree, pending.file) != nullptr;
        }
        else if (part.command == 0x2f && (part.words.size() == 24 || part.words.size() == 28))
        {
            const uint16_t fid = value16(part.words, 4);
            const size_t length = size_t(value16(part.words, 18)) << 16 | value16(part.words, 20);
            const Bytes data = payload(part, value16(part.words, 22), length);
            if (auto* opened = legacyPipe(user, tree, fid); opened && data.size() == length && length)
                append(*opened, direction, data, fields);
        }
        else if (part.command == 0x25 && part.words.size() == 32 &&
            value16(part.words, 0) == 0 && value16(part.words, 18) == 0 &&
            part.words[26] == 2 && value16(part.words, 28) == 0x26 &&
            value16(part.words, 2) == value16(part.words, 22))
        {
            pending.file = value16(part.words, 30);
            const size_t length = value16(part.words, 22);
            const Bytes data = payload(part, value16(part.words, 24), length);
            if (auto* opened = legacyPipe(user, tree, pending.file); opened &&
                data.size() == length && length)
            {
                append(*opened, direction, data, fields);
                keep = true;
            }
        }
        if (keep)
        {
            std::erase_if(legacyPending_, [&](const LegacyPending& item)
            {
                return item.process == process && item.message == mid && item.command == part.command &&
                    item.direction == direction;
            });
            if (legacyPending_.size() == MaxPending)
                legacyPending_.erase(legacyPending_.begin());
            legacyPending_.push_back(pending);
        }
        return;
    }

    const auto matched = std::find_if(legacyPending_.begin(), legacyPending_.end(), [&](const LegacyPending& item)
    {
        return item.process == process && item.message == mid && item.command == part.command &&
            item.direction != direction;
    });
    if (matched == legacyPending_.end())
        return;
    const LegacyPending pending = *matched;
    legacyPending_.erase(matched);
    const bool morePipeData = part.command == 0x25 &&
        ((value16(message, 10) & 0x4000) ? status == 0x80000005 : status == 0x00ea0001);
    if (status && !morePipeData)
        return;
    if (part.command == 0x75 && (part.words.size() == 6 || part.words.size() == 14) &&
        user == pending.user && tree)
    {
        // A successful connect replaces the returned TID; the disconnect flag also retires the old header TID.
        if (pending.disconnectTree && pending.tree)
        {
            std::erase_if(legacyTrees_,
                [&](const LegacyTree& item) { return item.user == pending.user && item.id == pending.tree; });
            std::erase_if(legacyPending_,
                [&](const LegacyPending& item) { return item.user == pending.user && item.tree == pending.tree; });
            dropPipes([&](const Pipe& item) { return item.session == pending.user && item.tree == pending.tree; });
        }
        std::erase_if(legacyTrees_, [&](const LegacyTree& item) { return item.user == user && item.id == tree; });
        std::erase_if(
            legacyPending_, [&](const LegacyPending& item) { return item.user == user && item.tree == tree; });
        dropPipes([&](const Pipe& item) { return item.session == user && item.tree == tree; });
        if (part.data.size() < 4 || !std::equal(part.data.begin(), part.data.begin() + 4, "IPC\0"))
            return;
        if (legacyTrees_.size() == MaxTrees)
        {
            const LegacyTree oldest = legacyTrees_.front();
            legacyTrees_.erase(legacyTrees_.begin());
            std::erase_if(legacyPending_,
                [&](const LegacyPending& item) { return item.user == oldest.user && item.tree == oldest.id; });
            dropPipes([&](const Pipe& item) { return item.session == oldest.user && item.tree == oldest.id; });
        }
        legacyTrees_.push_back({user, tree});
    }
    else if (part.command == 0xa2 && (part.words.size() == 68 || part.words.size() == 84) && user == pending.user &&
        tree == pending.tree &&
        std::any_of(legacyTrees_.begin(), legacyTrees_.end(),
            [&](const LegacyTree& item) { return item.user == user && item.id == tree; }) &&
        (value16(part.words, 63) == 1 || value16(part.words, 63) == 2))
    {
        const uint16_t fid = value16(part.words, 5);
        if (auto* opened = legacyPipe(user, tree, fid))
            forgetPending(*opened);
        dropPipes([&](const Pipe& item)
        {
            return item.session == user && item.tree == tree &&
                (uint16_t(item.file[0]) | uint16_t(item.file[1]) << 8) == fid;
        });
        if (pipes_.size() == MaxPipes)
        {
            forgetPending(pipes_.front());
            pipes_.erase(pipes_.begin());
        }
        std::array<uint8_t, 16> file{};
        file[0] = static_cast<uint8_t>(fid);
        file[1] = static_cast<uint8_t>(fid >> 8);
        pipes_.push_back({user, tree, file, true});
        recountRpcBytes();
    }
    else if (part.command == 0x2e && part.words.size() == 24 &&
        user == pending.user && tree == pending.tree)
    {
        const size_t length = size_t(value16(part.words, 14)) << 16 | value16(part.words, 10);
        const Bytes data = payload(part, value16(part.words, 12), length);
        if (auto* opened = legacyPipe(user, tree, pending.file); opened && data.size() == length && length)
            append(*opened, direction, data, fields);
    }
    else if (part.command == 0x25 && part.words.size() == 20 &&
        user == pending.user && tree == pending.tree && value16(part.words, 0) == 0 &&
        value16(part.words, 6) == 0 && value16(part.words, 2) >= value16(part.words, 12) &&
        value16(part.words, 16) == 0 && part.words[18] == 0)
    {
        const size_t length = value16(part.words, 12);
        const Bytes data = payload(part, value16(part.words, 14), length);
        if (auto* opened = legacyPipe(user, tree, pending.file); opened && data.size() == length && length)
            append(*opened, direction, data, fields);
    }
}
}
