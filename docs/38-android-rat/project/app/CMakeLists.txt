cmake_minimum_required(VERSION 3.22.1)
project("rat_native" CXX)

add_library(rat_native SHARED
    src/main/cpp/native_probe.cpp
)

find_library(log-lib log)

target_compile_options(rat_native PRIVATE
    -std=c++17
    -O2
    -fvisibility=hidden        # hide all symbols except JNI exports
    -fstack-protector-strong
)

target_compile_definitions(rat_native PRIVATE
    ANDROID
)

target_link_libraries(rat_native
    ${log-lib}
)
