#pragma once

#include "Model.h"
#include <functional>

namespace Cipherazzi
{
inline constexpr size_t LoopbackCaptureLimit = 65575;

class LoopbackCapture
{
public:
    using Sink = std::function<void(Bytes, int64_t)>;
    LoopbackCapture(Sink sink, Counters& counters);
    ~LoopbackCapture();
    LoopbackCapture(const LoopbackCapture&) = delete;
    LoopbackCapture& operator=(const LoopbackCapture&) = delete;
    void check();
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
