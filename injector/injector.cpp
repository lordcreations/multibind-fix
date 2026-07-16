#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <tlhelp32.h>

static DWORD rva_to_offset(const std::vector<uint8_t>& dll, DWORD rva) {
    auto dos = (IMAGE_DOS_HEADER*)dll.data();
    auto nt  = (IMAGE_NT_HEADERS*)(dll.data() + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
    }
    return rva;
}

struct LOADER_DATA {
    uint64_t image_base;
    uint64_t dllmain;
    uint32_t reason;
    uint64_t reserved;
};

static const uint8_t shellcode[] = {
    0x48, 0x89, 0xCE,
    0x48, 0x8B, 0x0E,
    0x8B, 0x56, 0x10,
    0x45, 0x33, 0xC0,
    0x48, 0x83, 0xEC, 0x28,
    0xFF, 0x56, 0x08,
    0x48, 0x83, 0xC4, 0x28,
    0x33, 0xC0,
    0xC3,
};

static DWORD find_process(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static bool read_dll(const char* path, std::vector<uint8_t>& out) {
    FILE* f;
    if (fopen_s(&f, path, "rb") || !f) return false;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    out.resize(len);
    fread(out.data(), 1, len, f);
    fclose(f);
    return true;
}

template<typename T>
static T* ptr_at(const std::vector<uint8_t>& dll, DWORD rva) {
    DWORD off = rva_to_offset(dll, rva);
    return (T*)(dll.data() + off);
}

static void init_cookie(HANDLE proc, uint64_t image_base,
                        const std::vector<uint8_t>& dll,
                        IMAGE_NT_HEADERS* nt) {
    auto loadcfg_rva = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    auto loadcfg_sz  = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
    if (!loadcfg_rva || !loadcfg_sz) return;

    auto loadcfg = ptr_at<IMAGE_LOAD_CONFIG_DIRECTORY64>(dll, loadcfg_rva);
    if (!loadcfg || !loadcfg->SecurityCookie) return;

    uint64_t cookie_addr = image_base + (loadcfg->SecurityCookie - nt->OptionalHeader.ImageBase);
    uint64_t cookie = GetCurrentProcessId() ^ GetCurrentThreadId() ^ (uint64_t)&cookie;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    cookie ^= ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
    cookie ^= pc.QuadPart;
    cookie &= 0xFFFFFFFFFFFFULL;
    if (cookie == 0x2B992DDFA232) cookie++;

    WriteProcessMemory(proc, (LPVOID)cookie_addr, &cookie, sizeof(cookie), nullptr);
}

static void init_exceptions(HANDLE proc, uint64_t image_base,
                            const std::vector<uint8_t>& dll,
                            IMAGE_NT_HEADERS* nt) {
    auto expdir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!expdir.Size) return;

    uint64_t exp_addr = image_base + expdir.VirtualAddress;
    DWORD count = expdir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    uint64_t func_addr = (uint64_t)GetProcAddress(ntdll, "RtlAddFunctionTable");
    if (!func_addr) return;

    uint8_t sc[64];
    int off = 0;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xEC; sc[off++] = 0x28;
    sc[off++] = 0x48; sc[off++] = 0xB9;
    memcpy(sc + off, &exp_addr, 8); off += 8;
    sc[off++] = 0xBA;
    memcpy(sc + off, &count, 4); off += 4;
    sc[off++] = 0x49; sc[off++] = 0xB8;
    memcpy(sc + off, &image_base, 8); off += 8;
    sc[off++] = 0x48; sc[off++] = 0xB8;
    memcpy(sc + off, &func_addr, 8); off += 8;
    sc[off++] = 0xFF; sc[off++] = 0xD0;
    sc[off++] = 0x48; sc[off++] = 0x83; sc[off++] = 0xC4; sc[off++] = 0x28;
    sc[off++] = 0xC3;

    LPVOID sc_addr = VirtualAllocEx(proc, nullptr, off, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(proc, sc_addr, sc, off, nullptr);
    HANDLE t = CreateRemoteThread(proc, nullptr, 0, (LPTHREAD_START_ROUTINE)sc_addr,
                                  nullptr, 0, nullptr);
    if (t) { WaitForSingleObject(t, 5000); CloseHandle(t); }
    VirtualFreeEx(proc, sc_addr, 0, MEM_RELEASE);
}

int main(int argc, char** argv) {
    const char* dll_path = argc > 1 ? argv[1] : "multibind-fix.dll";

    DWORD pid;
    do {
        pid = find_process(L"cs2.exe");
        if (!pid) Sleep(2000);
    } while (!pid);

    std::vector<uint8_t> dll;
    if (!read_dll(dll_path, dll)) return 1;

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) return 1;

    auto dos = (IMAGE_DOS_HEADER*)dll.data();
    auto nt  = (IMAGE_NT_HEADERS*)(dll.data() + dos->e_lfanew);

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        CloseHandle(proc);
        return 1;
    }

    DWORD image_size   = nt->OptionalHeader.SizeOfImage;
    uint64_t image_base = (uint64_t)VirtualAllocEx(proc, nullptr, image_size,
                                                    MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_EXECUTE_READWRITE);
    if (!image_base) {
        CloseHandle(proc);
        return 1;
    }

    WriteProcessMemory(proc, (LPVOID)image_base, dll.data(),
                       nt->OptionalHeader.SizeOfHeaders, nullptr);

    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint64_t target = image_base + sec[i].VirtualAddress;
        DWORD vsize = sec[i].Misc.VirtualSize;
        SIZE_T vsize_align = (vsize + 0xFFF) & ~0xFFF;
        std::vector<uint8_t> zero(vsize_align, 0);
        WriteProcessMemory(proc, (LPVOID)target, zero.data(), vsize_align, nullptr);

        if (sec[i].SizeOfRawData) {
            WriteProcessMemory(proc, (LPVOID)target,
                               dll.data() + sec[i].PointerToRawData,
                               sec[i].SizeOfRawData, nullptr);
        }
    }

    int64_t delta = (int64_t)(image_base - nt->OptionalHeader.ImageBase);
    if (delta) {
        auto reloc_dir = nt->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size) {
            uint8_t* reloc_buf = new uint8_t[reloc_dir.Size];
            SIZE_T read;
            ReadProcessMemory(proc, (LPVOID)(image_base + reloc_dir.VirtualAddress),
                              reloc_buf, reloc_dir.Size, &read);

            uintptr_t addr = 0;
            while (addr < reloc_dir.Size) {
                auto block = (IMAGE_BASE_RELOCATION*)(reloc_buf + addr);
                if (!block->SizeOfBlock) break;

                int count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                auto entries = (uint16_t*)(block + 1);

                for (int j = 0; j < count; j++) {
                    if (entries[j] >> 12 == IMAGE_REL_BASED_DIR64) {
                        uint64_t patch_addr = image_base + block->VirtualAddress + (entries[j] & 0xFFF);
                        uint64_t val;
                        ReadProcessMemory(proc, (LPVOID)patch_addr, &val, 8, nullptr);
                        val += delta;
                        WriteProcessMemory(proc, (LPVOID)patch_addr, &val, 8, nullptr);
                    }
                }
                addr += block->SizeOfBlock;
            }
            delete[] reloc_buf;
        }
    }

    auto import_dir = nt->OptionalHeader
        .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.Size) {
        auto desc = (IMAGE_IMPORT_DESCRIPTOR*)
            (dll.data() + rva_to_offset(dll, import_dir.VirtualAddress));

        for (size_t i = 0; desc[i].Name; i++) {
            char* mod_name = (char*)(dll.data() + rva_to_offset(dll, desc[i].Name));
            HMODULE mod = LoadLibraryA(mod_name);
            if (!mod) continue;

            DWORD thunk_rva = desc[i].OriginalFirstThunk
                            ? desc[i].OriginalFirstThunk
                            : desc[i].FirstThunk;
            auto thunk = (uintptr_t*)(dll.data() + rva_to_offset(dll, thunk_rva));
            uintptr_t* target_thunk = (uintptr_t*)(image_base + desc[i].FirstThunk);

            for (int j = 0; thunk[j]; j++) {
                uint64_t func = 0;
                if (thunk[j] & IMAGE_ORDINAL_FLAG64) {
                    func = (uint64_t)GetProcAddress(mod, (char*)(thunk[j] & 0xFFFF));
                } else {
                    auto by_name = (IMAGE_IMPORT_BY_NAME*)
                        (dll.data() + rva_to_offset(dll, (DWORD)thunk[j]));
                    func = (uint64_t)GetProcAddress(mod, by_name->Name);
                }
                if (func)
                    WriteProcessMemory(proc, (LPVOID)(target_thunk + j),
                                       &func, sizeof(func), nullptr);
            }
        }
    }

    init_cookie(proc, image_base, dll, nt);
    init_exceptions(proc, image_base, dll, nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_NOACCESS;
        DWORD ch = sec[i].Characteristics;
        if (ch & IMAGE_SCN_MEM_EXECUTE) {
            if (ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_EXECUTE_READWRITE;
            else if (ch & IMAGE_SCN_MEM_READ) prot = PAGE_EXECUTE_READ;
            else prot = PAGE_EXECUTE;
        } else {
            if (ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
            else if (ch & IMAGE_SCN_MEM_READ) prot = PAGE_READONLY;
        }
        if (prot != PAGE_NOACCESS) {
            DWORD old;
            VirtualProtectEx(proc, (LPVOID)(image_base + sec[i].VirtualAddress),
                             sec[i].Misc.VirtualSize, prot, &old);
        }
    }

    LOADER_DATA ld;
    ld.image_base  = image_base;
    ld.dllmain     = image_base + nt->OptionalHeader.AddressOfEntryPoint;
    ld.reason      = DLL_PROCESS_ATTACH;
    ld.reserved    = 0;

    LPVOID ld_target = VirtualAllocEx(proc, nullptr, sizeof(ld),
                                       MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(proc, ld_target, &ld, sizeof(ld), nullptr);

    LPVOID sc_target = VirtualAllocEx(proc, nullptr, sizeof(shellcode),
                                       MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(proc, sc_target, shellcode, sizeof(shellcode), nullptr);

    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)sc_target,
                                       ld_target, 0, nullptr);
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        VirtualFreeEx(proc, sc_target,  0, MEM_RELEASE);
        VirtualFreeEx(proc, ld_target,  0, MEM_RELEASE);
    }

    CloseHandle(proc);
    return 0;
}
