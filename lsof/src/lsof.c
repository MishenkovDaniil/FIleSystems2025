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
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *PROC_DIR = "/proc";
#define PATH_MAX_LEN 4096

static int get_user_uid (const char *username)
{
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        perror("getpwnam");
        return -1;
    }
    return pwd->pw_uid;
}

static int proc_owner_uid(pid_t pid, uid_t *out_uid)
{
    char path[PATH_MAX];
    char buf[512];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    while (fgets(buf, sizeof(buf), f))
    {
        if (strncmp(buf, "Uid:", 4) == 0)
        {
            /* формат: Uid:\tReal\tEffective\tSavedSet\tFilesystem\n */
            unsigned int real;
            if (sscanf(buf + 4, "%u", &real) == 1)
            {
                *out_uid = (uid_t)real;
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

static inline const char *cast_file_mod_to_str(const mode_t mode)
{
    switch (mode & S_IFMT) {
        case S_IFREG: return "S_IFREG";
        case S_IFDIR: return "S_IFDIR";
        case S_IFCHR: return "S_IFCHR";
        case S_IFBLK: return "S_IFBLK";
        case S_IFLNK: return "S_IFLNK";
        case S_IFIFO: return "S_IFIFO";
        case S_IFSOCK: return "S_IFSOCK";
        default:      return "UNKNOWN";
    }
}

static int get_process_name(const pid_t pid, char *process_name, const uint size)
{
    char process_name_file[64] = "";
    snprintf(process_name_file, sizeof(process_name_file), "/proc/%d/comm", pid);

    int fd = open(process_name_file, O_RDONLY);
    if (fd < 0)
    {
        perror("open:");
        return -1;
    }

    int cnt = read(fd,process_name, size);
    if (cnt < 0)
    {
        perror("read:");
        return -1;
    }

    process_name[cnt - 1] = '\0';
    if (close(fd) < 0)
    {
        perror("close:");
        return -1;
    }

    return 0;
}

static int print_pid_info(const pid_t pid)
{
    char process_name[512] = "";
    if(get_process_name(pid, process_name, 512) < 0)
        return -1;

    char filepath[PATH_MAX] = "";
    char real_filepath[PATH_MAX] = "";
    char path[PATH_MAX] = "";
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    DIR *proc_dir = opendir(path);
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (strcmp(entry->d_name, ".")  == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        snprintf(filepath, sizeof(filepath), "/proc/%d/fd/%s", pid, entry->d_name);
        if (readlink(filepath, real_filepath, PATH_MAX) < 0)
            return -1;
        struct stat stbuf;
        if (stat(real_filepath, &stbuf) == -1)
            continue;

        printf("%s\r\t\t%d\t%s\t%s\n", process_name, pid, cast_file_mod_to_str(stbuf.st_mode), real_filepath);
    }
}

int u_cmd(const char *username)
{
    uid_t user_uid = get_user_uid(username);
    if (user_uid < 0)ex
        return -1;

    DIR *proc_dir = opendir(PROC_DIR);
    struct dirent *entry;
    printf("PROCESS\t\tPID\t\tTYPE\t\tPATH\n");
    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit(entry->d_name[0]))
            continue;
        pid_t pid = (pid_t)atoi(entry->d_name);
        uid_t owner_uid;
        if (proc_owner_uid(pid, &owner_uid) < 0)
            return -1;
        if (owner_uid != user_uid)
            continue;

        print_pid_info(pid);
    }
    closedir(proc_dir);
}
