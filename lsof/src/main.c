#include "lsof.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [OPTION] [ARGUMENT] [FLAGS]\n", prog_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -u <user>       List files opened by user\n");
    fprintf(stderr, "  -p <PID>        List files opened by process\n");
    fprintf(stderr, "  +d <path>       List files opened in directory (shallow)\n");
    fprintf(stderr, "  +D <path>       List files opened in directory (recursive)\n");
    fprintf(stderr, "Flags:\n");
    fprintf(stderr, "  --all           Include memory-mapped files (libraries)\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s -u root                List files opened by root\n", prog_name);
    fprintf(stderr, "  %s -u root --all          List files and libraries for root\n", prog_name);
    fprintf(stderr, "  %s -p 1234                List files opened by process 1234\n", prog_name);
    fprintf(stderr, "  %s -p 1234 --all          List files and libraries for process 1234\n", prog_name);
    fprintf(stderr, "  %s +d /tmp                List files opened in /tmp\n", prog_name);
    fprintf(stderr, "  %s +D /home               List files opened in /home (recursive)\n", prog_name);
}

static int check_root_privileges(void)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "Error: This program requires root privileges\n");
        fprintf(stderr, "Please run with sudo: sudo %s [OPTION] [ARGUMENT]\n", "lsof_demo");
        return -1;
    }
    return 0;
}

int main(const int argc, const char **argv)
{
    if (argc < 3)
    {
        print_usage(argv[0]);
        return -1;
    }

    if (check_root_privileges() < 0)
    {
        return -1;
    }

    const char *option = argv[1];
    const char *argument = argv[2];

    /* Check if --all flag is present */
    int show_all = 0;
    for (int i = 3; i < argc; i++)
    {
        if (strcmp(argv[i], "--all") == 0)
        {
            show_all = 1;
            break;
        }
    }

    if (strcmp(option, "-h") == 0 || strcmp(option, "--help") == 0)
    {
        print_usage(argv[0]);
        return 0;
    }
    else if (strcmp(option, "-u") == 0 || strcmp(option, "--user") == 0)
    {
        if (show_all)
            return u_cmd_all(argument);
        else
            return u_cmd(argument);
    }
    else if (strcmp(option, "-p") == 0 || strcmp(option, "--pid") == 0)
    {
        if (show_all)
            return p_cmd_all(argument);
        else
            return p_cmd(argument);
    }
    else if (strcmp(option, "+d") == 0)
    {
        return d_cmd(argument);
    }
    else if (strcmp(option, "+D") == 0)
    {
        return D_cmd(argument);
    }
    else
    {
        fprintf(stderr, "Error: Unknown option '%s'\n", option);
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}