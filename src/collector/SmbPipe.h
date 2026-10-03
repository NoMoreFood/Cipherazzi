#pragma once

#include "Model.h"
#include <nlohmann/json.hpp>
#include <array>
#include <vector>

namespace Cipherazzi
{
// Tracks verified SMB named-pipe handles and reads complete DCE/RPC PDUs from their byte streams.
class SmbPipeInspection
{
public:
    void feed(Bytes message, int direction, nlohmann::json& fields);
    size_t memory() const;

private:
    struct Tree
    {
        uint64_t session{};
        uint32_t id{};
    };
    struct Pending
    {
        uint64_t session{};
        uint64_t message{};
        uint32_t tree{};
        std::array<uint8_t, 16> file{};
        uint8_t command{};
        int direction{};
    };
    struct Pipe
    {
        uint64_t session{};
        uint32_t tree{};
        std::array<uint8_t, 16> file{};
        bool legacy{};
        std::vector<uint8_t> rpc[2];
        bool disabled[2]{};
    };
    struct LegacyTree
    {
        uint16_t user{};
        uint16_t id{};
    };
    struct LegacyPending
    {
        uint32_t process{};
        uint16_t user{};
        uint16_t tree{};
        uint16_t message{};
        uint16_t file{};
        uint8_t command{};
        int direction{};
        bool disconnectTree{};
    };
    std::vector<Tree> trees_;
    std::vector<Pending> pending_;
    std::vector<Pipe> pipes_;
    std::vector<LegacyTree> legacyTrees_;
    std::vector<LegacyPending> legacyPending_;
    size_t rpcBytes_{};

    Pipe* pipe(uint64_t session, uint32_t tree, Bytes file);
    Pipe* legacyPipe(uint16_t user, uint16_t tree, uint16_t file);
    void forgetPending(const Pipe& pipe);
    void append(Pipe& pipe, int direction, Bytes bytes, nlohmann::json& fields);
    void feedLegacy(Bytes message, int direction, nlohmann::json& fields);
    void recountRpcBytes();
};
}
