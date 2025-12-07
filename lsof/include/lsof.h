#ifndef M_LSOF_H
#define M_LSOF_H

/* List files opened by specific user */
int u_cmd(const char *username);

/* List files opened by specific user including memory-mapped files */
int u_cmd_all(const char *username);

/* List files opened by specific process (PID) */
int p_cmd(const char *pid_str);

/* List files opened by specific process (PID) including memory-mapped files */
int p_cmd_all(const char *pid_str);

#endif /* M_LSOF_H */



