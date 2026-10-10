/*
  Exercise 04 — Length-Prefixed C2 Protocol
  -------------------------------------------
  Build a minimal C2 client that speaks the length-prefixed protocol described
  in theory.md. Run both client and server on localhost for testing.

  This exercise has two parts: SERVER (run first) and CLIENT (run second).
  Compile both from this single file — switch SERVER_MODE with a #define.

  Protocol:
    Both directions: [4-byte big-endian uint32 length][N bytes JSON string]

  Tasks:
  1. Implement sendMsg(SOCKET, string) — sends length prefix + data.
  2. Implement recvMsg(SOCKET) — receives length prefix then reads exactly that many bytes.
  3. SERVER mode:
     - Listen on 127.0.0.1:9876
     - Accept one client
     - Read a beacon message: JSON like {"type":"beacon","id":"bot001","host":"DESKTOP-XYZ"}
     - Print it
     - Send a command: {"type":"cmd","cmd":"shell","args":"whoami"}
     - Read the result
     - Print it
     - Close connection
  4. CLIENT mode:
     - Connect to 127.0.0.1:9876
     - Send beacon JSON
     - Read the command
     - "Execute" it (just print what you would do)
     - Send a fake result: {"type":"result","cmd":"shell","output":"DESKTOP-XYZ\\user"}
     - Close

  To compile as server: g++ -DSERVER_MODE -std=c++17 -Wall -o server.exe ex04_c2_protocol.cpp -lws2_32
  To compile as client: g++ -std=c++17 -Wall -o client.exe ex04_c2_protocol.cpp -lws2_32
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <cstdint>

// YOUR CODE HERE — sendMsg and recvMsg

#ifdef SERVER_MODE
void runServer() {
    // YOUR CODE HERE
}
int main() {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    runServer();
    WSACleanup();
    return 0;
}
#else
void runClient() {
    // YOUR CODE HERE
}
int main() {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    runClient();
    WSACleanup();
    return 0;
}
#endif
