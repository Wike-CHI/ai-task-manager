#pragma once
#include "types.h"

inline ProcessIoRate CalculateIoRate(const ProcessIoSample* previous, const ProcessIoSample& current) {
    ProcessIoRate rate;
    if (!current.valid || !current.pid || !current.creation) return rate;
    if (!previous || !previous->valid) { rate.state = IoRateState::FirstSample; return rate; }
    if (previous->pid != current.pid || previous->creation != current.creation) {
        rate.state = IoRateState::IdentityChanged; return rate;
    }
    if (current.tickMs <= previous->tickMs) { rate.state = IoRateState::InvalidInterval; return rate; }
    if (current.readBytes < previous->readBytes || current.writeBytes < previous->writeBytes) {
        rate.state = IoRateState::CounterReset; return rate;
    }
    rate.elapsedSeconds = static_cast<double>(current.tickMs - previous->tickMs) / 1000.0;
    rate.readBytesPerSecond = static_cast<double>(current.readBytes - previous->readBytes) / rate.elapsedSeconds;
    rate.writeBytesPerSecond = static_cast<double>(current.writeBytes - previous->writeBytes) / rate.elapsedSeconds;
    rate.state = IoRateState::Measured;
    return rate;
}
