#include "lsof.h"

#include <stdio.h>

int main(const int argc, const char **argv)
{

    if (argc < 3)
    {
        fprintf(stderr, "Error: need param\n");
        return -1;
    }

    // parse_args...
    u_cmd(argv[2]);

    return 0;
}