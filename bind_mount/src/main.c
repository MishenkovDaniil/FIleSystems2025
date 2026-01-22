#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "bind_mount.h"

static void usage(const char *p)
{
	fprintf(stderr, "Usage: %s --user username --source /path/to/src -- cmd [args...]\n", p);
}

int main(int argc, char **argv)
{
	if (geteuid() != 0)
	{
		fprintf(stderr, "This program must be run as root.\n");
		return 2;
	}

	const char *username = NULL;
	const char *source = NULL;
	int idx = 1;
	while (idx < argc)
	{
		if (strcmp(argv[idx], "--user") == 0)
		{
			idx++;
			if (idx >= argc)
			{
				usage(argv[0]);
				return 1;
			}
			username = argv[idx++];
		}
		else if (strcmp(argv[idx], "--source") == 0)
		{
			idx++;
			if (idx >= argc)
			{
				usage(argv[0]);
				return 1;
			}
			source = argv[idx++];
		}
		else if (strcmp(argv[idx], "--") == 0)
		{
			idx++;
			break;
		}
		else
		{
			usage(argv[0]);
			return 1;
		}
	}

	if (!username || !source || idx >= argc)
	{
		usage(argv[0]);
		return 1;
	}

	struct passwd *pw = getpwnam(username);
	if (!pw)
	{
		perror("getpwnam");
		return 1;
	}

	uid_t uid = pw->pw_uid;
	gid_t gid = pw->pw_gid;

	char rootpath[PATH_MAX];
	snprintf(rootpath, sizeof(rootpath), "/tmp/bind_root_%s_%d", username, (int) getpid());

	if (create_root_dir(rootpath, uid, gid, 0755) != 0)
	{
		fprintf(stderr, "Failed to create root dir %s\n", rootpath);
		return 1;
	}

	// unshare mount namespace - create new mount namespace
	// so that we won't affect other processes by new mounts/unmounts (if MS_PRIVATE)
	if (unshare(CLONE_NEWNS) != 0)
	{
		perror("unshare");
		return 1;
	}

	// make mount private to avoid affecting other mounts
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
	{
		perror("mount MS_PRIVATE");
		return 1;
	}

	if (do_bind_mount(source, rootpath) != 0)
	{
		fprintf(stderr, "Failed to bind mount %s -> %s\n", source, rootpath);
		return 1;
	}

	if (chdir(rootpath) != 0)
	{
		perror("chdir root");
		return 1;
	}
	if (chroot(rootpath) != 0)
	{
		perror("chroot");
		return 1;
	}
	if (chdir("/") != 0)
	{
		perror("chdir /");
		return 1;
	}

	mkdir("/mnt", 0755);
	mount("tmpfs", "/mnt", "tmpfs", 0, "size=16M");

	if (initgroups(username, gid) != 0) //set supplementary groups
	{
		perror("initgroups");
		return 1;
	}
	if (setgid(gid) != 0)
	{
		perror("setgid");
		return 1;
	}
	if (setuid(uid) != 0)
	{
		perror("setuid");
		return 1;
	}

	char **cmd = &argv[idx];
	execvp(cmd[0], cmd); // give management to cmd
	perror("execvp");
	return 1;
}

