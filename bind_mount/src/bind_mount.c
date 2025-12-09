#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "bind_mount.h"

int create_root_dir(const char *path, uid_t uid, gid_t gid, mode_t mode)
{
	if (!path)
		return -1;
	if (mkdir(path, mode) != 0)
	{
		if (errno != EEXIST)
		{
			perror("mkdir");
			return -1;
		}
	}

	if (chown(path, uid, gid) != 0)
	{
		perror("chown");
		return -1;
	}
	if (chmod(path, mode) != 0)
	{
		perror("chmod");
		return -1;
	}
	return 0;
}

int do_bind_mount(const char *source, const char *target)
{
	if (!source || !target)
		return -1;

	// ensure target exists
	struct stat st;
	if (stat(target, &st) != 0)
	{
		perror("stat target");
		return -1;
	}

	if (mount(source, target, NULL, MS_BIND | MS_REC, NULL) != 0)
	{
		perror("mount --bind");
		return -1;
	}
	return 0;
}

