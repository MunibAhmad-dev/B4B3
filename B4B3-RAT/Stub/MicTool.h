/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/
#pragma once
#ifndef MICTOOL_H
#define MICTOOL_H

#include <string>

namespace MicTool {
    // Record audio from the default microphone for durationSec seconds.
    // Saves a WAV file to outPath; returns true on success.
    bool Record(const std::string& outPath, int durationSec);
}

#endif
