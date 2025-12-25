#ifndef PARSE_H
#define PARSE_H

#include <stdint.h>

void print_ext2_info(int fd);
void list_root_dir(int fd);
int print_file_data_by_name(int fd, const char *name);
int print_file_data_by_path(int fd, const char *path, int print_data);

#endif /* PARSE_H */