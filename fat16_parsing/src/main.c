#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "parse.h"


#define img_path "/home/daniil/MIPT_shiz/course_1-4/file_systems/hw/fat16_parsing/imgs/disk.img"

int main()
{
    fprintf(stderr, "Main start.\n");
    int fd = open(img_path, O_RDONLY);
    if (fd < 0)
    {
        perror("failed to open img " img_path);
        return -1;
    }

    print_fat_info(fd);
    uint32_t root_dir_start = find_root_dir_offset(fd);
    printf("RootDirStart = %u\n", root_dir_start);
    list_files(fd);


    print_file_data(fd, "big.txt");

    close(fd);

    return 0;
}