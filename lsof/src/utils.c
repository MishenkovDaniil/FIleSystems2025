#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>

#include "utils.h"

/*************** FORMATTED OUTPUT *****************/

/* Format file size in human-readable format */
static void format_size(off_t size, char *buf, size_t buf_size)
{
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double dsize = (double)size;
    int unit_idx = 0;

    while (dsize >= 1024.0 && unit_idx < 4) {
        dsize /= 1024.0;
        unit_idx++;
    }

    if (unit_idx == 0) {
        snprintf(buf, buf_size, "%.0f%s", dsize, units[unit_idx]);
    } else {
        snprintf(buf, buf_size, "%.1f%s", dsize, units[unit_idx]);
    }
}

void print_formatted_row(const char *process, pid_t pid, const char *type, off_t size, const char *path)
{
    char size_str[64];
    format_size(size, size_str, sizeof(size_str));

    printf("%-*s %-*d %-*s %-*s %-*s\n",
           COL_PROCESS_WIDTH, process,
           COL_PID_WIDTH, pid,
           COL_TYPE_WIDTH, type,
           COL_SIZE_WIDTH, size_str,
           COL_PATH_WIDTH, path);
}

void print_formatted_row_s(const char *process, const char * pid, const char *type, off_t size, const char *path)
{
    char size_str[64];
    format_size(size, size_str, sizeof(size_str));

    printf("%-*s %-*s %-*s %-*s %-*s\n",
           COL_PROCESS_WIDTH, process,
           COL_PID_WIDTH, pid,
           COL_TYPE_WIDTH, type,
           COL_SIZE_WIDTH, size_str,
           COL_PATH_WIDTH, path);
}

void print_header_row()
{
    printf("%-*s %-*s %-*s %-*s %-*s\n",
           COL_PROCESS_WIDTH, "PROCESS",
           COL_PID_WIDTH, "PID",
           COL_TYPE_WIDTH, "TYPE",
           COL_SIZE_WIDTH, "SIZE",
           COL_PATH_WIDTH, "PATH");
}

const char *cast_file_mod_to_str(const mode_t mode)
{
    switch (mode & S_IFMT)
    {
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
/**************************************************/

/*************FILES DETECTING********************/
static bool is_file_in_dir_shallow(const char *file_path, const char *target_dir)
{
    // check prefix equality
    size_t dir_len = strlen(target_dir);
    if (strncmp(file_path, target_dir, dir_len) != 0)
        return false;

    const char *rel_path = file_path + dir_len;
    if (rel_path[0] == '/')
        rel_path++;

    for (const char *p = rel_path; *p; p++)
    {
        if (*p == '/')
            return false;
    }

    return true;
}

static bool is_file_in_dir_deep(const char *file_path, const char *target_dir)
{
    size_t dir_len = strlen(target_dir);

    if (strncmp(file_path, target_dir, dir_len) != 0)
        return false;

    if (target_dir[dir_len - 1] != '/')
    {
        if (file_path[dir_len] != '/' && file_path[dir_len] != '\0')
            return false;
    }

    return true;
}

static int is_file_in_dir(const char *file_path, const char *target_dir, bool deep)
{
    return deep ? is_file_in_dir_deep(file_path, target_dir)
                : is_file_in_dir_shallow(file_path, target_dir);
}
/**************************************************/


/*************** UTILITY FUNCTIONS *****************/
int get_user_uid(const char *username, uid_t *out_uid)
{
    assert(username);
    assert(out_uid);

    struct passwd *pwd = getpwnam(username);
    if (!pwd)
    {
        // perror("getpwnam"); //prints 'Success' if not found
        return -1;
    }

    *out_uid = pwd->pw_uid;
    return 0;
}

int proc_owner_uid(pid_t pid, uid_t *out_uid)
{
    assert(out_uid);
    assert(pid > 0);

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

int get_process_name(const pid_t pid, char *process_name, const unsigned int size)
{
    assert(process_name);
    assert(pid > 0);

    char process_name_file[64] = "";
    snprintf(process_name_file, sizeof(process_name_file), "/proc/%d/comm", pid);

    int fd = open(process_name_file, O_RDONLY);
    if (fd < 0)
    {
        perror("open:");
        return -1;
    }

    int cnt = read(fd, process_name, size);
    if (cnt < 0)
    {
        perror("read:");
        return -1;
    }

    if (cnt != 0)
        process_name[cnt - 1] = '\0';

    if (close(fd) < 0)
    {
        perror("close:");
        return -1;
    }

    return 0;
}

static void print_mmap_files(pid_t pid)
{
    char process_name[512] = "";
    if(get_process_name(pid, process_name, 512) < 0)
        return;

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file)
        return;

    char line[512];
    /* /proc/%d/maps string format:
     *          address          perms  offset   dev     ino                     pathname
     * 7d20f037f000-7d20f0383000 r--p  00000000 103:02 10885850 /usr/lib/x86_64-linux-gnu/libgpg-error.so.0.32.1
     */
    while (fgets(line, sizeof(line), maps_file))
    {
        char pathname[256] = "";
        // Parsing the line - taking the last "word" as pathname
        char *last_space = strrchr(line, ' ');
        if (last_space && last_space[1] != '\n')
            sscanf(last_space + 1, "%255s", pathname);

        if (strlen(pathname) == 0 || pathname[0] != '/')
            continue;

        struct stat stbuf;
        if (stat(pathname, &stbuf) == -1)
            continue;

        // Showing only .so libraries and other files
        if (strstr(pathname, ".so") || strstr(pathname, ".a"))
        {
            print_formatted_row_s(process_name, "mem",
                cast_file_mod_to_str(stbuf.st_mode), stbuf.st_size, pathname);
        }
    }

    fclose(maps_file);
}

int print_all_pid_info(const pid_t pid)
{
    print_pid_info(pid);
    print_mmap_files(pid);
    return 0;
}

int print_pid_info(const pid_t pid)
{
    char process_name[512] = "";
    if(get_process_name(pid, process_name, 512) < 0)
        return -1;

    char filepath[PATH_MAX] = "";
    char real_filepath[PATH_MAX] = "";
    char path[PATH_MAX] = "";
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);

    DIR *proc_dir = opendir(path);
    if (!proc_dir)
    {
        perror("opendir:");
        return -1;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".")  == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "/proc/%d/fd/%s", pid, entry->d_name);
        ssize_t bytes = readlink(filepath, real_filepath, PATH_MAX);
        if (bytes < 0)
        {
            perror("readlink:");
            closedir(proc_dir);
            return -1;
        }
        real_filepath[bytes] = '\0';

        struct stat stbuf;
        if (stat(real_filepath, &stbuf) == -1)
            continue;

        print_formatted_row(process_name, pid, cast_file_mod_to_str(stbuf.st_mode), stbuf.st_size, real_filepath);
    }

    closedir(proc_dir);
    return 0;
}

int print_pid_info_filtered(const pid_t pid, const char *dirpath, bool deep)
{
    char process_name[512] = "";
    if (get_process_name(pid, process_name, 512) < 0)
        return -1;

    char filepath[PATH_MAX] = "";
    char real_filepath[PATH_MAX] = "";
    char path[PATH_MAX] = "";
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);

    DIR *proc_dir = opendir(path);
    if (!proc_dir)
        return -1;

    struct dirent *entry = NULL;
    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "/proc/%d/fd/%s", pid, entry->d_name);

        ssize_t bytes = readlink(filepath, real_filepath, PATH_MAX - 1);
        if (bytes < 0)
            continue;

        real_filepath[bytes] = '\0';

        // Filter by directory
        if (!is_file_in_dir(real_filepath, dirpath, deep))
            continue;

        struct stat stbuf;
        if (stat(real_filepath, &stbuf) == -1)
            continue;

        print_formatted_row(process_name, pid, cast_file_mod_to_str(stbuf.st_mode),
                           stbuf.st_size, real_filepath);
    }

    closedir(proc_dir);

    /* Also check cwd, root and exe */
    const char *special_links[] = {"cwd", "root", "exe"};
    for (int i = 0; i < 3; i++)
    {
        snprintf(filepath, sizeof(filepath), "/proc/%d/%s", pid, special_links[i]);

        ssize_t bytes = readlink(filepath, real_filepath, PATH_MAX - 1);
        if (bytes < 0)
            continue;

        real_filepath[bytes] = '\0';

        if (!is_file_in_dir(real_filepath, dirpath, deep))
            continue;

        struct stat stbuf;
        if (stat(real_filepath, &stbuf) == -1)
            continue;

        print_formatted_row(process_name, pid, cast_file_mod_to_str(stbuf.st_mode),
                           stbuf.st_size, real_filepath);
    }

    return 0;
}
