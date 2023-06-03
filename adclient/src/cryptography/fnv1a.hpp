#ifndef AXISANTICHEAT_FNV1A_HPP
#define AXISANTICHEAT_FNV1A_HPP

#define HASH_CT(str)                                                       \
    []() [[msvc::forceinline]] {                                           \
        constexpr uint32_t hash_out{axisdefender::fnv1a::hash_ctime(str)}; \
                                                                           \
        return hash_out;                                                   \
    }()

#define HASH(str) axisdefender::fnv1a::hash_rtime(str)

namespace axisdefender {
    constexpr uint32_t magic_num = 0x13377;
    constexpr uint32_t xor_key_1 = __TIME__[2] ^ magic_num;
    constexpr uint32_t xor_key_2 = __TIME__[4];
    constexpr uint32_t xor_key_offset = (xor_key_1 ^ xor_key_2);

    namespace fnv1a {
        constexpr uint32_t fnv_prime_value = 0x01000193;

        __forceinline consteval uint32_t hash_ctime(const char *input, unsigned val = 0x811c9dc5 ^ xor_key_offset) noexcept
        {
            return input[0] == '\0' ? val : hash_ctime(input + 1, (val ^ *input) * fnv_prime_value);
        }

        __forceinline constexpr uint32_t hash_rtime(const char *input, unsigned val = 0x811c9dc5 ^ xor_key_offset) noexcept
        {
            return input[0] == '\0' ? val : hash_rtime(input + 1, (val ^ *input) * fnv_prime_value);
        }
    }// namespace fnv1a
}// namespace axisdefender

#endif//AXISANTICHEAT_FNV1A_HPP
