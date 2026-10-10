/*
  Exercise 01 — TCP Client
  --------------------------
  Tasks:
  1. Write a function: SOCKET connectTo(const char* host, uint16_t port)
     Returns a connected SOCKET or INVALID_SOCKET on failure.
     Use WSAStartup, socket(), inet_pton(), connect().

  2. Write: bool sendAll(SOCKET s, const char* data, int len)
     Sends all bytes, looping if send() returns less than requested.

  3. Write: std::string recvLine(SOCKET s)
     Receives bytes until '\n' is encountered, returns the line (without '\n').

  4. In main():
     Connect to "towel.blinkenlights.nl" on port 23 (a public ASCII art telnet server).
     OR if that's blocked: connect to any server you control.
     Read and print 5 lines of whatever comes back.
     Close the socket.

     If you don't have an internet-accessible server, write a minimal echo server
     in a second program (ex02) and connect to 127.0.0.1:9999.

  5. Add a timeout: use setsockopt with SO_RCVTIMEO to set a 5-second receive timeout.
     If no data arrives within 5 seconds, print "timeout" and exit.

  Compile:
    g++ -std=c++17 -Wall -o ex01.exe ex01_tcp_client.cpp -lws2_32
*/

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

// YOUR CODE HERE

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    // YOUR CODE HERE

    WSACleanup();
    return 0;
}
