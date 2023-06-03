#ifndef AEROANTICHEAT_IMAGE_HPP
#define AEROANTICHEAT_IMAGE_HPP

#include <deque>
#include "safe_call.hpp"

namespace pe {
    struct section_data_t {
        uint32_t name_hash;
        size_t va, size, v_size;
    };

    struct iat_data_t {
        PIMAGE_THUNK_DATA original_first_thunk;
        PIMAGE_THUNK_DATA thunk;
        PIMAGE_IMPORT_BY_NAME import_by_name;
    };

    class parse_image {
        PIMAGE_SECTION_HEADER _section_header{}; PIMAGE_NT_HEADERS64 _nt_headers64;
        PIMAGE_OPTIONAL_HEADER64 _optional_header64{}; PIMAGE_IMPORT_DESCRIPTOR _import_desc{};
        void *_base_address;
    public:
        __forceinline ~parse_image() {
            this->_nt_headers64 = nullptr; this->_section_header = nullptr;
        }

        __forceinline explicit parse_image(void *image_address) {
            auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER *>(image_address);

            if (dos_headers->e_magic != IMAGE_DOS_SIGNATURE)
                return;

            this->_base_address = image_address;
            this->_nt_headers64 = reinterpret_cast<PIMAGE_NT_HEADERS64>((uintptr_t) image_address + dos_headers->e_lfanew);
            this->_optional_header64 = &this->_nt_headers64->OptionalHeader;
        }

        __forceinline uintptr_t base() { return reinterpret_cast<uintptr_t>(this->_base_address); }
        __forceinline PIMAGE_NT_HEADERS64 nt() { return this->_nt_headers64; }

        __forceinline std::deque<section_data_t> get_sections() {
            std::deque<section_data_t> section_data;

            this->_section_header = IMAGE_FIRST_SECTION(this->_nt_headers64);

            for (int i = 0; i < this->_nt_headers64->FileHeader.NumberOfSections; i++) {
                auto& sec = this->_section_header[i];

                section_data.push_back({
                        SAFE_HASH_R((const char*)sec.Name),
                        (size_t)sec.VirtualAddress,
                        (size_t)sec.SizeOfRawData,
                        (size_t)sec.Misc.VirtualSize
                });
            }

            return section_data;
        }

        __forceinline const std::deque<iat_data_t>& get_iat() {
            std::deque<iat_data_t> iat_data_array;

            auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                    reinterpret_cast<BYTE*>(this->_base_address) +
                    this->_nt_headers64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            );

            while (import_desc->OriginalFirstThunk) {
                iat_data_t iat_data{};

                iat_data.original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                        reinterpret_cast<BYTE*>(this->_base_address) +
                        import_desc->OriginalFirstThunk
                );

                iat_data.thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
                        reinterpret_cast<BYTE*>(this->_base_address) +
                        import_desc->FirstThunk
                );

                while (iat_data.thunk->u1.Function) {
                    iat_data.import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                            reinterpret_cast<BYTE*>(iat_data.original_first_thunk->u1.AddressOfData) +
                            reinterpret_cast<uintptr_t>(this->_base_address)
                    );

                    iat_data_array.push_back(iat_data);

                    ++iat_data.thunk;
                    ++iat_data.original_first_thunk;
                }

                ++import_desc;
            }

            return iat_data_array;
        }
    };
}// namespace pe

#endif//AEROANTICHEAT_IMAGE_HPP
