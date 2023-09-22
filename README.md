### Module Library

A Windows library that iterates internally loaded modules with the PEB and can get information about modules, sections,
and exports (even forwarded exports!).

**Examples**

```c++
// Get the address and size of kernel32.dll.
auto [module_address, module_size] = module::GetModuleAddress("kernel32.dll");

// Get the address and size of the .rdata section.
auto [rdata_address, rdata_size] = module::GetSectionAddress(module_address, ".rdata");

// Find the address of the export VirtualAlloc.
uint64_t export_address = module::GetExportAddress(module_address, "VirtualAlloc");

// Find the address of VirtualAlloc by ordinal.
export_address = module::GetExportAddress(module_address, "", true, 1536);
```

**Requires**

- C++ 20 or later.
- Your own Windows headers (I recommend [phnt](https://github.com/winsiderss/systeminformer/tree/master/phnt)).