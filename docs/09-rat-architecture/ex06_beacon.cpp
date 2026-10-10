/*
  Exercise 06 — WinINet HTTPS Beacon
  -------------------------------------
  Build a working beacon that talks to the existing B4B3 C2 server.
  (Run the C2 server locally or on your VPS.)

  Tasks:
  1. Write: std::string getBotId()
     Read "MachineGuid" from:
       HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
     Return it. This is unique per Windows install.

  2. Write: std::string buildBeaconJson()
     Returns a JSON string:
     {
       "key":  "<authkey from config>",
       "id":   "<machine_guid>",
       "host": "<computername>",
       "user": "<username>",
       "os":   "<os_version>",
       "ip":   "<local_ip>"
     }
     Use GetComputerNameA, GetUserNameA, RtlGetVersion or registry for OS version.
     Use GetAdaptersInfo or Winsock for IP.

  3. Write: std::string c2Post(const char* host, INTERNET_PORT port,
                                const char* path, const std::string& body)
     As described in theory.md. Skip cert validation (self-signed cert on C2).

  4. Write: void c2Loop(const char* host, INTERNET_PORT port)
     Loop:
       - Build beacon JSON
       - POST to /b (or /check — check your C2 server's routes)
       - Parse response JSON:  {"cmd":"ping"} or {"cmd":"shell","args":"whoami"}
       - If cmd == "shell": run ExecShell(args), POST result to /r
       - If cmd == "screenshot": capture, POST JPEG as multipart or base64
       - If cmd == "ping": POST {"output":"pong"} to /r
       - Sleep 5000 + jitter

  5. In main():
     Start c2Loop pointing at 127.0.0.1:4444 (or your VPS).
     Run the C2 server first: cd c2-server && node server.js
     Watch the dashboard for your bot appearing.

  Compile:
    g++ -std=c++17 -Wall -o ex06.exe ex06_beacon.cpp
        -lwininet -ladvapi32 -lkernel32 -liphlpapi -lws2_32
*/

#include <windows.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>

// YOUR CODE HERE

int main() {
    // YOUR CODE HERE — connect to C2 and beacon
    return 0;
}
