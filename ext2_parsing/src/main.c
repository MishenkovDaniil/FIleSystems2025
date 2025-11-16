#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "parse.h"

#define IMG_PATH "/home/daniil/MIPT_shiz/course_1-4/file_systems/hw/ext2_parsing/imgs/disk.img"

int main(int argc, char **argv)
{
    const char *img = IMG_PATH;
    if (argc > 1)
        img = argv[1];

    int fd = open(img, O_RDONLY);
    if (fd < 0)
    {
        perror("failed to open image");
        return -1;
    }

    print_ext2_info(fd);
    list_root_dir(fd);

    if (argc > 2)
    {
        if (print_file_data_by_path(fd, argv[2]) < 0)
        {
            fprintf(stderr, "Failed to read path '%s'\n", argv[2]);
        }
    }

    close(fd);
    return 0;
}