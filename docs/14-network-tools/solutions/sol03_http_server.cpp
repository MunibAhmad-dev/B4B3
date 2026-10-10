// sol03_http_server.cpp — Minimal HTTP/1.1 Server
// Handles one connection at a time. Educational use only.
//
// Routes:
//   GET /         → 200 HTML page showing request headers
//   GET /health   → 200 plain "OK"
//   GET *         → 404
//
// Compile:
//   g++ -std=c++17 -Wall -o sol03.exe solutions/sol03_http_server.cpp -lws2_32
//
// Usage:
//   sol03.exe [port]     default 8080

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

static volatile bool g_running = true;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// HTTP date in RFC 1123 format
// ---------------------------------------------------------------------------
static std::string http_date()
{
    time_t now = time(NULL);
    struct tm t;
    gmtime_s(&t, &now);
    char buf[64];
    strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &t);
    return buf;
}

// ---------------------------------------------------------------------------
// Parse first line of HTTP request: "METHOD /path HTTP/version"
// Returns false on parse error.
// ---------------------------------------------------------------------------
static bool parse_request_line(const std::string& raw,
                                std::string& method,
                                std::string& path,
                                std::string& version,
                                std::string& headers_block)
{
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return false;

    std::string line = raw.substr(0, line_end);
    size_t s1 = line.find(' ');
    if (s1 == std::string::npos) return false;
    size_t s2 = line.find(' ', s1 + 1);
    if (s2 == std::string::npos) return false;

    method  = line.substr(0, s1);
    path    = line.substr(s1 + 1, s2 - s1 - 1);
    version = line.substr(s2 + 1);

    // Collect raw headers (everything after the request line, before empty line)
    size_t headers_start = line_end + 2;
    size_t headers_end   = raw.find("\r\n\r\n", headers_start);
    if (headers_end != std::string::npos) {
        headers_block = raw.substr(headers_start, headers_end - headers_start);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Build HTTP response
// ---------------------------------------------------------------------------
static std::string build_response(int status_code,
                                   const std::string& status_text,
                                   const std::string& content_type,
                                   const std::string& body)
{
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
    oss << "Date: "           << http_date()       << "\r\n";
    oss << "Server: sol03-lab/1.0\r\n";
    oss << "Content-Type: "   << content_type      << "\r\n";
    oss << "Content-Length: " << body.size()        << "\r\n";
    oss << "Connection: close\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

// ---------------------------------------------------------------------------
// HTML page for GET /
// ---------------------------------------------------------------------------
static std::string make_index_page(const std::string& method,
                                    const std::string& path,
                                    const std::string& headers_raw)
{
    std::ostringstream html;
    html << "<!DOCTYPE html><html><head>"
         << "<title>sol03 HTTP Lab</title>"
         << "<style>body{font-family:monospace;padding:2em;background:#1e1e1e;color:#d4d4d4}"
         << "h1{color:#4ec9b0}table{border-collapse:collapse;width:100%}"
         << "td,th{border:1px solid #555;padding:6px 12px;text-align:left}"
         << "th{background:#333;color:#9cdcfe}</style>"
         << "</head><body>"
         << "<h1>sol03 HTTP/1.1 Lab Server</h1>"
         << "<p>Request: <code>" << method << " " << path << "</code></p>"
         << "<h2>Request Headers</h2>"
         << "<table><tr><th>Header</th><th>Value</th></tr>";

    // Parse each header line
    std::istringstream iss(headers_raw);
    std::string hline;
    while (std::getline(iss, hline)) {
        if (!hline.empty() && hline.back() == '\r') hline.pop_back();
        size_t colon = hline.find(':');
        if (colon != std::string::npos) {
            std::string name = hline.substr(0, colon);
            std::string value = hline.substr(colon + 1);
            while (!value.empty() && value.front() == ' ') value.erase(0, 1);
            // Escape HTML
            auto esc = [](const std::string& s) {
                std::string out;
                for (char c : s) {
                    if      (c == '<')  out += "&lt;";
                    else if (c == '>')  out += "&gt;";
                    else if (c == '&')  out += "&amp;";
                    else                out += c;
                }
                return out;
            };
            html << "<tr><td>" << esc(name) << "</td><td>" << esc(value) << "</td></tr>";
        }
    }

    html << "</table>"
         << "<p style='margin-top:2em;color:#666'>Routes: GET /  GET /health  (all others → 404)</p>"
         << "</body></html>";
    return html.str();
}

// ---------------------------------------------------------------------------
// Handle one connection
// ---------------------------------------------------------------------------
static void handle_connection(SOCKET client, struct sockaddr_in* client_addr)
{
    char remote_ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &client_addr->sin_addr, remote_ip, sizeof(remote_ip));
    int remote_port = ntohs(client_addr->sin_port);

    // Read request (up to 16 KB)
    char recv_buf[16384] = {};
    int total = 0;
    while (total < (int)sizeof(recv_buf) - 1) {
        int n = recv(client, recv_buf + total, (int)(sizeof(recv_buf) - 1 - total), 0);
        if (n <= 0) break;
        total += n;
        if (strstr(recv_buf, "\r\n\r\n")) break;  // full headers received
    }

    std::string raw(recv_buf, total);
    std::string method, path, version, headers_raw;
    std::string response;
    int status_code = 400;
    std::string status_text = "Bad Request";

    if (!parse_request_line(raw, method, path, version, headers_raw)) {
        response = build_response(400, "Bad Request", "text/plain", "Bad Request\r\n");
        status_code = 400;
        status_text = "Bad Request";
    } else if (path == "/health") {
        response = build_response(200, "OK", "text/plain", "OK\r\n");
        status_code = 200;
        status_text = "OK";
    } else if (path == "/") {
        std::string body = make_index_page(method, path, headers_raw);
        response = build_response(200, "OK", "text/html; charset=utf-8", body);
        status_code = 200;
        status_text = "OK";
    } else {
        std::string body = "404 Not Found: " + path + "\r\n";
        response = build_response(404, "Not Found", "text/plain", body);
        status_code = 404;
        status_text = "Not Found";
    }

    // Send response
    send(client, response.c_str(), (int)response.size(), 0);
    closesocket(client);

    // Log
    time_t now = time(NULL);
    struct tm t;
    localtime_s(&t, &now);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", &t);
    printf("[%s] %s:%d \"%s %s %s\" %d\n",
           ts, remote_ip, remote_port,
           method.c_str(), path.c_str(), version.c_str(),
           status_code);
}

// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    int port = 8080;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0 || port > 65535) { fprintf(stderr, "Invalid port\n"); return 1; }
    }

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) { fprintf(stderr, "socket() failed\n"); return 1; }

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((u_short)port);

    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed on port %d: %d\n", port, WSAGetLastError());
        return 1;
    }
    listen(srv, SOMAXCONN);

    printf("=== sol03 HTTP/1.1 Lab Server ===\n");
    printf("Listening on http://0.0.0.0:%d\n", port);
    printf("Routes: GET /  GET /health\n");
    printf("Press Ctrl+C to stop.\n\n");

    // Set a timeout on accept so we can check g_running
    DWORD timeout_ms = 1000;
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    while (g_running) {
        struct sockaddr_in client_addr = {};
        int client_len = sizeof(client_addr);
        SOCKET client = accept(srv, (struct sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) continue;
            if (!g_running) break;
            fprintf(stderr, "accept() error: %d\n", err);
            continue;
        }
        handle_connection(client, &client_addr);
    }

    closesocket(srv);
    WSACleanup();
    printf("\nServer stopped.\n");
    return 0;
}
