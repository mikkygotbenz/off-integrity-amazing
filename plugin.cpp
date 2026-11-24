#include <windows.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <psapi.h>

static bool write_memory(void* dst, const void* src, size_t size)
{
    DWORD old_protect = 0;
    if (!VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &old_protect))
        return false;

    std::memcpy(dst, src, size);

    DWORD temp = 0;
    VirtualProtect(dst, size, old_protect, &temp);
    FlushInstructionCache(GetCurrentProcess(), dst, size);
    return true;
}

static uintptr_t find_pattern(const char* module_name, const char* signature)
{
    HMODULE module = GetModuleHandleA(module_name);
    if (!module)
        return 0;

    MODULEINFO info{};
    if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info)))
        return 0;

    uintptr_t start = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
    uintptr_t end = start + info.SizeOfImage;

    std::vector<int> pattern;
    const char* cur = signature;

    while (*cur)
    {
        if (*cur == ' ')
        {
            ++cur;
            continue;
        }

        if (*cur == '?')
        {
            ++cur;
            if (*cur == '?')
                ++cur;
            pattern.push_back(-1);
        }
        else
        {
            char byte_str[3] = { cur[0], cur[1], 0 };
            pattern.push_back(static_cast<int>(std::strtoul(byte_str, nullptr, 16)));
            cur += 2;
        }
    }

    size_t pattern_size = pattern.size();
    if (!pattern_size)
        return 0;

    for (uintptr_t i = start; i < end - pattern_size; ++i)
    {
        bool found = true;

        for (size_t j = 0; j < pattern_size; ++j)
        {
            if (pattern[j] != -1 &&
                pattern[j] != *reinterpret_cast<unsigned char*>(i + j))
            {
                found = false;
                break;
            }
        }

        if (found)
            return i;
    }

    return 0;
}

static void retintegrity()
{
    uintptr_t integrity = find_pattern(
        "aggmain.asi",
        "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 56 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? 8B 75 ? 8B CE E8 ? ? ? ? E8 ? ? ? ? 85 F6 74 ? 6A ? 56 E8 ? ? ? ? 83 C4 ? 33 C0 8B 4D ? 64 89 0D ? ? ? ? 59 5E 8B E5 5D C2 ? ? CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 EC"
    );

    if (!integrity)
        return;

    const unsigned char ret = 0xC3;
    write_memory(reinterpret_cast<void*>(integrity), &ret, sizeof(ret));
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(module);
        retintegrity();
        break;

    case DLL_PROCESS_DETACH:
        break;

    default:
        break;
    }

    return TRUE;
}