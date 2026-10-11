#pragma once
#ifndef CLIP_MON_H
#define CLIP_MON_H
#include "common.h"

namespace ClipMon {
    void Start();             // Spawn background thread polling clipboard every 500 ms
    void Stop();              // Signal background thread to exit
    std::string Dump();       // Return accumulated entries and clear the buffer
    bool IsRunning();
}

#endif
