#ifndef PARSE_H
#define PARSE_H

#include <stdint.h>
#include <unistd.h>

void print_fat_info(int fd);
void print_root_dir_info(int fd);

void list_files(int fat_fd);
void print_file_data(int fat_fd, char *filename);

#endif /* PARSE_H */