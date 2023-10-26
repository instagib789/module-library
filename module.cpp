#include "module.hpp"

#include <algorithm>
#include <cwctype>
#include <memory>

std::tuple<uint64_t, size_t> module::GetModuleAddress(const std::wstring_view& w_module_name) {
    PEB* p_peb = NtCurrentTeb()->ProcessEnvironmentBlock;

    // Loop through loaded modules.
    for (LIST_ENTRY* p_list_entry = p_peb->Ldr->InLoadOrderModuleList.Flink;
         p_list_entry != &p_peb->Ldr->InLoadOrderModuleList;
         p_list_entry = p_list_entry->Flink) {
        auto* p_entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(p_list_entry);

        // Compare the module names, case-insensitive.
        if (std::ranges::equal(w_module_name, std::wstring_view(p_entry->BaseDllName.Buffer),
                               [](wchar_t a, wchar_t b) { return (std::towlower(a) == std::towlower(b)); })) {
            auto module_address = reinterpret_cast<uint64_t>(p_entry->DllBase);

            // Get and check headers' sanity.
            auto* p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_address);
            if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                continue;
            }
            auto* p_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_address + p_dos_header->e_lfanew);
            if (p_nt_header->Signature != IMAGE_NT_SIGNATURE) {
                continue;
            }
            if (p_nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                continue;
            }

            // Return with the address and size.
            return std::make_tuple(module_address, p_nt_header->OptionalHeader.SizeOfImage);
        }
    }
    return std::make_tuple(0, 0);
}

std::tuple<uint64_t, size_t> module::GetModuleAddress(const std::string_view& module_name) {
    size_t w_size = module_name.size();
    auto w_module_name = std::make_unique<wchar_t[]>(w_size + 1);

    size_t converted = 0;
    mbstowcs_s(&converted, w_module_name.get(), w_size + 1, module_name.data(), w_size);

    return GetModuleAddress(w_module_name.get());
}

size_t module::GetModuleSize(uint64_t module_address) {
    auto* p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_address);
    auto* p_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_address + p_dos_header->e_lfanew);

    return p_nt_header->OptionalHeader.SizeOfImage;
}

std::tuple<uint32_t, size_t> module::GetSectionRva(uint64_t module_address, const std::string_view& section_name) {
    auto* p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_address);
    auto* p_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_address + p_dos_header->e_lfanew);

    // Loop through sections.
    IMAGE_SECTION_HEADER* section_array = IMAGE_FIRST_SECTION(p_nt_header);
    for (uint16_t i = 0; i < p_nt_header->FileHeader.NumberOfSections; i++) {
        // Section names can only be 8 characters long and may not have null-terminators.
        auto found_section_name = reinterpret_cast<const char*>(section_array[i].Name);
        if (section_name.compare(std::string_view(found_section_name, strnlen_s(found_section_name, 8))) == 0) {
            return std::make_tuple(section_array[i].VirtualAddress, section_array[i].Misc.VirtualSize);
        }
    }
    return std::make_tuple(0, 0);
}

std::tuple<uint64_t, size_t> module::GetSectionAddress(uint64_t module_address, const std::string_view& section_name) {
    auto [section_rva, section_size] = GetSectionRva(module_address, section_name);
    if (section_rva == 0) {
        return std::make_tuple(0, 0);
    }
    return std::make_tuple(module_address + section_rva, section_size);
}

uint32_t module::GetExportRva(uint64_t module_address, const std::string_view& export_name, bool by_ordinal,
                              uint16_t ordinal) {
    auto* p_dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(module_address);
    auto* p_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(module_address + p_dos_header->e_lfanew);

    auto* p_export_directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        module_address + p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    uint32_t export_directory_size = p_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    // Function and name array both store offsets from the module base.
    auto* function_array = reinterpret_cast<uint32_t*>(module_address + p_export_directory->AddressOfFunctions);
    auto* name_array = reinterpret_cast<uint32_t*>(module_address + p_export_directory->AddressOfNames);
    // Holds both values that are used to index into the function array, and calculate the ordinal.
    auto* entry_index_array = reinterpret_cast<uint16_t*>(module_address + p_export_directory->AddressOfNameOrdinals);

    for (uint32_t i = 0; i < p_export_directory->NumberOfFunctions; ++i) {
        if (by_ordinal) {
            // Get ordinal, we have to add the base ordinal value.
            uint16_t found_ordinal = static_cast<uint16_t>(p_export_directory->Base) + entry_index_array[i];
            if (ordinal != found_ordinal) {
                continue;
            }
        } else {
            if (i >= p_export_directory->NumberOfNames) {
                break;
            }
            // Get starting address of name.
            const char* found_export_name = reinterpret_cast<const char*>(module_address + name_array[i]);
            if (export_name.compare(found_export_name) != 0) {
                continue;
            }
        }
        // Get Function rva by indexing with the entry array index.
        uint32_t function_rva = function_array[entry_index_array[i]];

        // If function address is within the export directory range, then it's a forward string.
        uint64_t export_address = module_address + function_rva;
        if (export_address >= reinterpret_cast<uint64_t>(p_export_directory) &&
            export_address < reinterpret_cast<uint64_t>(p_export_directory) + export_directory_size) {
            return FindForwardedExportRva(reinterpret_cast<const char*>(export_address));
        } else {
            return function_rva;
        }
    }
    return 0;
}

uint64_t module::GetExportAddress(uint64_t module_address, const std::string_view& export_name, bool by_ordinal,
                                  uint16_t ordinal) {
    uint32_t export_rva = GetExportRva(module_address, export_name, by_ordinal, ordinal);
    if (export_rva == 0) {
        return 0;
    }
    return module_address + export_rva;
}

uint32_t module::FindForwardedExportRva(const std::string_view& forward_string) {
    // Forward strings contains the module name and export name separated by a period, 'ModuleName.ExportName'.
    size_t split_off = forward_string.find('.');
    if (split_off == std::string::npos) {
        return 0;
    }
    ++split_off;

    size_t w_size = split_off + (sizeof(L"dll") / sizeof(wchar_t));
    auto w_module_name = std::make_unique<wchar_t[]>(w_size);

    size_t converted = 0;
    mbstowcs_s(&converted, w_module_name.get(), split_off + 1, forward_string.data(), split_off);
    wcscat_s(w_module_name.get(), w_size, L"dll");

    auto [module_address, module_size] = GetModuleAddress(w_module_name.get());
    if (module_address == 0) {
        return 0;
    }
    return GetExportRva(module_address, forward_string.substr(split_off));
}