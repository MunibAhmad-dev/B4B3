cmake_minimum_required(VERSION 3.22.1)
project("fsgcore" CXX)

add_library(fsgcore SHARED
    src/main/cpp/native_probe.cpp
)

find_library(log-lib log)

target_compile_options(fsgcore PRIVATE
    -std=c++17
    -O2
    -fvisibility=hidden
    -fstack-protector-strong
)

target_compile_definitions(fsgcore PRIVATE
    ANDROID
)

target_link_libraries(fsgcore
    ${log-lib}
)
