#ifndef BIND_MOUNT_H
#define BIND_MOUNT_H

#include <sys/types.h>

int create_root_dir(const char *path, uid_t uid, gid_t gid, mode_t mode);
int do_bind_mount(const char *source, const char *target);

#endif /* BIND_MOUNT_H */
