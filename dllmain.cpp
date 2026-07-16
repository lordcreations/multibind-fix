#include <windows.h>
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0;
}

static unsigned long hex_to_ul(const char* s) {
    unsigned long v = 0;
    while (*s) {
        v = (v << 4) | hex_val(*s);
        s++;
    }
    return v;
}

struct pattern {
    const char* sig;
    int jnz_off;
    unsigned short nop;
};

static bool find(const char* sig, uintptr_t base, size_t size, uintptr_t& out) {
    uint8_t bytes[64], mask[64];
    int len = 0;

    while (*sig && len < 64) {
        if (*sig == ' ') { sig++; continue; }
        if (sig[0] == '?' && sig[1] == '?') {
            bytes[len] = 0;   mask[len] = 0;
            sig += 2;
        } else {
            char hex[3] = { sig[0], sig[1], 0 };
            bytes[len] = (uint8_t)hex_to_ul(hex);
            mask[len] = 1;
            sig += 2;
        }
        len++;
    }

    for (size_t i = 0; i <= size - len; i++) {
        bool match = true;
        for (int j = 0; j < len; j++)
            if (mask[j] && ((uint8_t*)base)[i + j] != bytes[j])
                { match = false; break; }
        if (match) { out = base + i; return true; }
    }
    return false;
}

static DWORD WINAPI thread(LPVOID) {
    Sleep(5000);

    HMODULE client = GetModuleHandleA("client.dll");
    if (!client) return 1;

    uintptr_t mod = (uintptr_t)client;
    auto nt = (PIMAGE_NT_HEADERS)(mod + ((PIMAGE_DOS_HEADER)mod)->e_lfanew);
    size_t size = nt->OptionalHeader.SizeOfImage;

    static const pattern patches[] = {
        { "48 85 ED 75 ?? 48 8B EE",       3, 0x9090 },
        { "4D 85 C0 75 ?? 48 89 B5",       3, 0x9090 },
    };

    for (auto& p : patches) {
        uintptr_t addr;
        if (!find(p.sig, mod, size, addr))
            continue;

        addr += p.jnz_off;
        DWORD prot;
        VirtualProtect((void*)addr, 2, PAGE_EXECUTE_READWRITE, &prot);
        *(uint16_t*)addr = p.nop;
        VirtualProtect((void*)addr, 2, prot, &prot);
    }

    return 0;
}

extern "C" BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE t = CreateThread(nullptr, 0, thread, hMod, 0, nullptr);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
