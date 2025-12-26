#pragma once

#ifndef PROCESS_HIDER_H

#define PROCESS_HIDER_H

#include <Windows.h>
#include <TlHelp32.h>

int hide_proc_via_pid(DWORD pid);
int hide_proc_via_name(const char* proc_name);
int unhide_proc_via_pid(DWORD pid);
int unhide_proc_via_name(const char* proc_name);
void list_proc(void);
void print_help(void);

BOOL WINAPI hooked_Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
BOOL WINAPI hooked_Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
void install_hooks(void);
void remove_hooks(void);

typedef struct hidden_process {
    DWORD pid;
    char name[MAX_PATH];
    struct hidden_process* next;
} hidden_process_t;

extern hidden_process_t* hidden_list;

#endif 
