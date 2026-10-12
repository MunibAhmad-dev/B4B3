#pragma once
#ifndef WMIPERSIST_H
#define WMIPERSIST_H
#include "common.h"

namespace WMIPersist {
    // Install a WMI permanent event subscription:
    //   __EventFilter (Win32_LogonSession creation) +
    //   CommandLineEventConsumer (runs cmd) +
    //   __FilterToConsumerBinding
    // Survives reboots — fires cmd each time any user logs on.
    // Detection: Sysmon EventID 19 (WmiEvent filter), 20 (WmiEvent consumer),
    //   21 (WmiEvent binding) — highest-fidelity WMI persistence detection signals.
    // MITRE T1546.003 — used by APT29, FIN7, Lazarus for stealthy persistence.
    std::string Install(const std::string& name, const std::string& cmd);

    // Remove the three WMI objects created by Install().
    std::string Remove(const std::string& name);

    // Enumerate all __EventFilter objects in ROOT\subscription to detect persistence.
    std::string List();
}

#endif
