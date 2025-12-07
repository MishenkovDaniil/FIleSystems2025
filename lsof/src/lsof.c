/*
    lsof options:
        -u <user>           -- files, opened by user, by default $USER
        -U                  -- unix sockets
        -c<name>            -- show info about files, which keep open processes, starting from <name>
        +d <path-to-dit>    -- show all opened files in dir, and dirs at top level, by default cur dir
        +d <path-to-dit>    -- show all opened files in dir, and files in child dirs to its complete depth, by default cur dir
        -d !!!
        -p <PID>            -- show all processes opened by PID process
*/

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

static const char *PROC_DIR = "/proc";

int u_cmd(const char *username)
{
    uid_t user_uid;
    int rc = get_user_uid(username, &user_uid);
    if (rc < 0)
    {
        fprintf(stderr, "Error: User '%s' not found in the system\n", username);
        return -1;
    }

    DIR *proc_dir = opendir(PROC_DIR);
    if (!proc_dir)
    {
        perror("opendir");
        return -1;
    }

    struct dirent *entry;
    print_header_row();
    int found_any = 0;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0]))
            continue;
        pid_t pid = (pid_t)atoi(entry->d_name);
        uid_t owner_uid;
        if (proc_owner_uid(pid, &owner_uid) < 0)
            continue;
        if (owner_uid != user_uid)
            continue;

        print_pid_info(pid);
        found_any = 1;
    }
    closedir(proc_dir);

    return 0;
}

int p_cmd(const char *pid_str)
{
    pid_t pid = (pid_t)atoi(pid_str);
    return print_pid_info(pid);
}

int u_cmd_all(const char *username)
{
    uid_t user_uid;
    int rc = get_user_uid(username, &user_uid);
    if (rc < 0)
    {
        fprintf(stderr, "Error: User '%s' not found in the system\n", username);
        return -1;
    }

    DIR *proc_dir = opendir(PROC_DIR);
    if (!proc_dir)
    {
        perror("opendir");
        return -1;
    }

    struct dirent *entry;
    print_header_row();
    int found_any = 0;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0]))
            continue;
        pid_t pid = (pid_t)atoi(entry->d_name);
        uid_t owner_uid;
        if (proc_owner_uid(pid, &owner_uid) < 0)
            continue;
        if (owner_uid != user_uid)
            continue;

        print_all_pid_info(pid);
        found_any = 1;
    }
    closedir(proc_dir);

    return 0;
}

int p_cmd_all(const char *pid_str)
{
    pid_t pid = (pid_t)atoi(pid_str);
    return print_all_pid_info(pid);
}