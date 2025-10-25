#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "parse.h"

#define img_path "/home/daniil/MIPT_shiz/course_1-4/file_systems/hw/fat16_parsing/imgs/disk.img"

int main()
{
    int fd = open(img_path, O_RDONLY);
    if (fd < 0)
    {
        perror("failed to open img " img_path);
        return -1;
    }

    print_fat_info(fd);
    list_files(fd);

    print_file_data(fd, "big.txt");
    print_file_data(fd, "file1.txt");
    print_file_data(fd, "file2.c");
    print_file_data(fd, "file3.o");
    print_file_data(fd, "file3.jpg");

    close(fd);

    return 0;
}