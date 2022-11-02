#ifndef __UTILS__H
#define __UTILS__H

#include "seal/seal.h"

using namespace std;

class Timer {
public:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point end_;
    Timer();
    void start();
    void end();
    long double end_and_get();
    void reset();
    long double get_time_in_milliseconds();
};

class Metrics{
    public:
    map<string, uint64_t> metrics_;
};

#endif
