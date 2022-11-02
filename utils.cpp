#include "utils.h"

using namespace std;

Timer::Timer(){
    start_ = chrono::steady_clock::now();
    end_ = chrono::steady_clock::now();
}

void Timer::start(){
    start_ = chrono::steady_clock::now();
}

void Timer::end(){
    end_ = chrono::steady_clock::now();
}

long double Timer::end_and_get(){
    end_ = chrono::steady_clock::now();
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end_ - start_);
    return elapsed.count();
}

long double Timer::get_time_in_milliseconds(){
    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end_ - start_);
    return elapsed.count();
}