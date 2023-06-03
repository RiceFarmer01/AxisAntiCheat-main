#ifndef AEROANTICHEAT_HOOKS_HPP
#define AEROANTICHEAT_HOOKS_HPP

namespace axisdefender {
    namespace hooks {
        inline axisdefender::iat_hook query_performance_counter_hk;

        BOOL query_performance_counter(LARGE_INTEGER *lpPerformanceCount);
    }// namespace hooks
}// namespace axisdefender

#endif//AEROANTICHEAT_HOOKS_HPP
