#pragma once

#include "Engine.h"
#include <array>
#include <chrono>
#include <climits>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <semaphore>
#include <stdexcept>

namespace Cipherazzi
{
class PacketQueue
{
public:
    struct Packet
    {
        int64_t timestamp;
        PacketKind kind;
        Bytes bytes;
        PacketOrigin origin;
    };

    explicit PacketQueue(size_t packets = 65536, size_t bytes = 8 * 1024 * 1024,
        size_t maximumPacket = PacketMonitorCaptureLimit) :
        capacity_(packets), byteCapacity_(bytes), maximumPacket_(maximumPacket),
        slots_(new Slot[packets]), bytes_(new uint8_t[bytes])
    {
        if (!packets || !maximumPacket || maximumPacket > bytes / 2)
            throw std::invalid_argument("Packet queue requires positive slots and at least two maximum-size packets");
    }

    bool push(Bytes packet, PacketKind kind, int64_t timestamp,
        PacketOrigin origin = PacketOrigin::PacketMonitor) noexcept
    {
        // Callback work uses preallocated storage and never waits for the packet consumer. Capture sources
        // wait only for each other's copy, so a packet is refused when the queue is full and never otherwise.
        if (packet.size() > maximumPacket_)
            return false;
        {
            std::lock_guard lock(producer_);
            const auto head = head_.load(std::memory_order_relaxed);
            const auto remaining = byteCapacity_ - byteHead_ % byteCapacity_;
            const auto padding = remaining < packet.size() ? remaining : 0;
            const auto required = padding + packet.size();
            if (head - tail_.load(std::memory_order_acquire) >= capacity_ ||
                byteHead_ - byteTail_.load(std::memory_order_acquire) + required > byteCapacity_)
                return false;
            const auto offset = byteHead_ + padding;
            slots_[head % capacity_] = {timestamp, offset, packet.size(), kind, origin};
            std::memcpy(bytes_.get() + offset % byteCapacity_, packet.data(), packet.size());
            byteHead_ += required;
            head_.store(head + 1, std::memory_order_release);
        }
        available_.release();
        return true;
    }

    std::optional<Packet> take(std::chrono::milliseconds timeout)
    {
        if (!available_.try_acquire_for(timeout))
            return {};
        const auto tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire))
            return {};
        const auto& slot = slots_[tail % capacity_];
        return Packet{slot.timestamp, slot.kind,
            Bytes(bytes_.get() + slot.offset % byteCapacity_, slot.size), slot.origin};
    }

    void release() noexcept
    {
        // The single consumer releases the view only after parsing its bytes.
        const auto tail = tail_.load(std::memory_order_relaxed);
        const auto& slot = slots_[tail % capacity_];
        byteTail_.store(slot.offset + slot.size, std::memory_order_release);
        tail_.store(tail + 1, std::memory_order_release);
    }

    void wake() { available_.release(); }

private:
    struct Slot
    {
        int64_t timestamp;
        size_t offset;
        size_t size;
        PacketKind kind;
        PacketOrigin origin;
    };
    size_t capacity_;
    size_t byteCapacity_;
    size_t maximumPacket_;
    std::unique_ptr<Slot[]> slots_;
    std::unique_ptr<uint8_t[]> bytes_;
    std::atomic<size_t> head_{};
    size_t byteHead_{};
    std::array<uint8_t, 64> padding_{};
    std::atomic<size_t> tail_{};
    std::atomic<size_t> byteTail_{};
    std::mutex producer_;
    std::counting_semaphore<INT_MAX> available_{0};
};
}
