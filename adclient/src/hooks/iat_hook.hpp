#ifndef AEROANTICHEAT_IAT_HOOK_HPP
#define AEROANTICHEAT_IAT_HOOK_HPP

namespace axisdefender {
    class iat_hook {
        void *_original = nullptr;

    public:
        __forceinline bool create_hook(const uint32_t &module_hash, const uint32_t &import_name, void *function_address) noexcept {
            auto image_address = SAFE_MODULE_HASH(module_hash);

            if (!image_address)
                return false;

            auto image = pe::parse_image(image_address);
            auto import_address_table = image.get_iat();

            if (import_address_table.empty())
                return false;

            for (auto &import : import_address_table) {
                const char *import_func_name = (const char *)import.import_by_name->Name;

                if (HASH(import_func_name) != import_name)
                    continue;

                unsigned long old_protect = 0;

                this->_original = reinterpret_cast<void *>(import.thunk->u1.Function);
                SAFE_CALL(VirtualProtect)(import.thunk, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &old_protect);
                import.thunk->u1.Function = (uint64_t)function_address;
                SAFE_CALL(VirtualProtect)(import.thunk, sizeof(uintptr_t), old_protect, &old_protect);
            }

            return true;
        }

        template<typename T>
        __forceinline T call_original() {
            return reinterpret_cast<T>(this->_original);
        }
    };
}// namespace axisdefender

#endif//AEROANTICHEAT_IAT_HOOK_HPP
