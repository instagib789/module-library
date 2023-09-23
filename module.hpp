#ifndef INCLUDED_MODULE_HPP_
#define INCLUDED_MODULE_HPP_

#include <string>
#include <tuple>

namespace module {

std::tuple<uint64_t, size_t> GetModuleAddress(const std::wstring_view& w_module_name);
std::tuple<uint64_t, size_t> GetModuleAddress(const std::string_view& module_name);

size_t GetModuleSize(uint64_t module_address);

std::tuple<uint32_t, size_t> GetSectionRva(uint64_t module_address, const std::string_view& section_name);
std::tuple<uint64_t, size_t> GetSectionAddress(uint64_t module_address, const std::string_view& section_name);

uint32_t GetExportRva(uint64_t module_address, const std::string_view& export_name, bool by_ordinal = false,
                      uint16_t ordinal = 0);
uint64_t GetExportAddress(uint64_t module_address, const std::string_view& export_name, bool by_ordinal = false,
                          uint16_t ordinal = 0);

uint32_t FindForwardedExportRva(const std::string_view& forward_string);

}  // namespace module

#endif  // INCLUDED_MODULE_HPP_