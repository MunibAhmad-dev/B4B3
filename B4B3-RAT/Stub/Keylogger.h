/*
MIT License
Copyright (c) 2020 4B4DB4B3
*/
#pragma once
#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <string>

namespace Keylogger {
    void        Start();
    void        Stop();
    std::string Dump();      // returns captured text and clears buffer
    bool        IsRunning();
}

#endif
