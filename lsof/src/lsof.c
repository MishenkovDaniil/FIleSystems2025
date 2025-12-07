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
    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (!isdigit(entry->d_name[0]))
            continue;

        pid_t pid = (pid_t)atoi(entry->d_name);
        uid_t owner_uid;
        if (proc_owner_uid(pid, &owner_uid) < 0)
            continue;
        if (owner_uid != user_uid)
            continue;

        print_pid_info(pid);
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

int d_cmd(const char *dirpath)
{
    struct stat dir_stat;
    if (stat(dirpath, &dir_stat) < 0)
    {
        perror("stat");
        return -1;
    }

    if (!S_ISDIR(dir_stat.st_mode))
    {
        fprintf(stderr, "Error: '%s' is not a directory\n", dirpath);
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

    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (!isdigit(entry->d_name[0]))
            continue;

        pid_t pid = (pid_t)atoi(entry->d_name);
        print_pid_info_filtered(pid, dirpath, false);
    }

    closedir(proc_dir);
    return 0;
}

int D_cmd(const char *dirpath)
{
    struct stat dir_stat;
    if (stat(dirpath, &dir_stat) < 0)
    {
        perror("stat");
        return -1;
    }

    if (!S_ISDIR(dir_stat.st_mode))
    {
        fprintf(stderr, "Error: '%s' is not a directory\n", dirpath);
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

    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (!isdigit(entry->d_name[0]))
            continue;

        pid_t pid = (pid_t)atoi(entry->d_name);
        print_pid_info_filtered(pid, dirpath, true);
    }

    closedir(proc_dir);
    return 0;
}
