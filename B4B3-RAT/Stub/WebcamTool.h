/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/
#pragma once
#ifndef WEBCAMTOOL_H
#define WEBCAMTOOL_H

#include <string>

namespace WebcamTool {
    // Capture one frame from the default webcam.
    // Saves a JPEG to outPath; returns true on success.
    bool CaptureFrame(const std::string& outPath);
}

#endif
