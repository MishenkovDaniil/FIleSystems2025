#ifndef LSOF_UTILS_H
#define LSOF_UTILS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

/* Column widths for formatted output */
#define COL_PROCESS_WIDTH 20
#define COL_PID_WIDTH 10
#define COL_TYPE_WIDTH 15
#define COL_SIZE_WIDTH 15
#define COL_PATH_WIDTH 40

/* Get UID by username */
int get_user_uid(const char *username, uid_t *out_uid);

/* Get process owner UID */
int proc_owner_uid(pid_t pid, uid_t *out_uid);

/* Convert file mode to string representation */
const char *cast_file_mod_to_str(const mode_t mode);

/* Get process name from /proc/[pid]/comm */
int get_process_name(const pid_t pid, char *process_name, const unsigned int size);

/* Print formatted output row with fixed column widths */
void print_formatted_row(const char *process, pid_t pid, const char *type, off_t size, const char *path);
/* Print formatted output row with PID as string */
void print_formatted_row_s(const char *process, const char * pid, const char *type, off_t size, const char *path);

/* Print header row for the output */
void print_header_row(void);

/* Print all opened files for a given PID */
int print_pid_info(const pid_t pid);

/* Print all information (opened files and memory-mapped files) for a given PID */
int print_all_pid_info(const pid_t pid);

/* Print PID info filtered by directory (shallow or deep) */
int print_pid_info_filtered(const pid_t pid, const char *dirpath, bool deep);

#endif /* LSOF_UTILS_H */
