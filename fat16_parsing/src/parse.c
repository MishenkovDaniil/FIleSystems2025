#include <linux/msdos_fs.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <strings.h>
void print_fat_info(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count  = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return;
    }

    // Правильно читаем multi-byte поля (little-endian)
    uint16_t sector_size = buf.sector_size[0] | (buf.sector_size[1] << 8);
    uint16_t dir_entries = buf.dir_entries[0] | (buf.dir_entries[1] << 8);
    uint16_t sectors = buf.sectors[0] | (buf.sectors[1] << 8);

    printf("FAT 16 INFO\n");
    printf("\tsystem_id: %.8s\n", buf.system_id);
    printf("\tsector_size: %u bytes\n", sector_size);
    printf("\tsec_per_clus: %u\n", buf.sec_per_clus);
    printf("\treserved: %u\n", buf.reserved);
    printf("\tfats: %u\n", buf.fats);
    printf("\tdir_entries: %u\n", dir_entries);
    printf("\tsectors: %u\n", sectors);
    printf("\tmedia: 0x%02X\n", buf.media);
    printf("\tfat_length: %u sectors\n", buf.fat_length);
    printf("\tsecs_track: %u\n", buf.secs_track);
    printf("\theads: %u\n", buf.heads);
    printf("\thidden: %u\n", buf.hidden);
    printf("\ttotal_sect: %u\n", buf.total_sect);
}

uint32_t find_root_dir_offset(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return 0;
    }

    uint16_t bytes_per_sector = buf.sector_size[0] | (buf.sector_size[1] << 8);
    uint32_t root_dir_sector = buf.reserved + (buf.fats * buf.fat_length);

    return root_dir_sector * bytes_per_sector;
}

uint32_t find_root_dir_block_offset(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return 0;
    }
    return buf.reserved + (buf.fats * buf.fat_length);
}

uint32_t find_FAT_block_offset(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return 0;
    }
    return buf.reserved;
}

uint32_t find_data_block_offset(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return 0;
    }
    uint16_t dir_entries = buf.dir_entries[0] | (buf.dir_entries[1] << 8);
    uint16_t bytes_per_sector = buf.sector_size[0] | (buf.sector_size[1] << 8);
    uint16_t root_dir_sectors = (dir_entries * 32 + bytes_per_sector - 1) / bytes_per_sector;
    return buf.reserved + (buf.fats * buf.fat_length) + root_dir_sectors;
}

void print_root_dir_info(int fd)
{
    struct fat_boot_sector buf;

    ssize_t count = pread(fd, (char *)&buf, sizeof(struct fat_boot_sector), 0);
    if (count < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fd, strerror(errno));
        return;
    }

    uint16_t bytes_per_sector = buf.sector_size[0] | (buf.sector_size[1] << 8);
    uint16_t root_entries = buf.dir_entries[0] | (buf.dir_entries[1] << 8);

    uint32_t root_dir_sector = buf.reserved + (buf.fats * buf.fat_length);

    uint32_t root_dir_offset = root_dir_sector * bytes_per_sector;

    // Размер root directory в байтах (каждая запись 32 байта)
    uint32_t root_dir_size = root_entries * 32;
    uint32_t root_dir_sectors = (root_dir_size + bytes_per_sector - 1) / bytes_per_sector;

    printf("\n=== Root Directory Location ===\n");
    printf("Bytes per sector: %u\n", bytes_per_sector);
    printf("Reserved sectors: %u\n", buf.reserved);
    printf("Number of FATs: %u\n", buf.fats);
    printf("FAT size (sectors): %u\n", buf.fat_length);
    printf("Root dir entries: %u\n", root_entries);
    printf("Root dir starts at sector: %u\n", root_dir_sector);
    printf("Root dir offset (bytes): %u (0x%X)\n", root_dir_offset, root_dir_offset);
    printf("Root dir size: %u bytes (%u sectors)\n", root_dir_size, root_dir_sectors);
    printf("Data area starts at sector: %u\n", root_dir_sector + root_dir_sectors);
}

inline static ssize_t read_block(int fat_fd, uint32_t block_num, uint8_t *buffer, size_t block_size)
{
    off_t offset = block_num * block_size;
    return pread(fat_fd, buffer, block_size, offset);
}

static void convert_fat_name(uint8_t fatname[MSDOS_NAME], uint8_t buf[MSDOS_NAME + 1])
{
    int i = 0;
    int k = 0;

    //copy name
    const uint8_t EXT_SIZE = 3;
    for (; i < MSDOS_NAME - EXT_SIZE && fatname[i] != ' '; ++i, ++k)
    {
        buf[k] = fatname[i];
    }

    //put diff between name and extension
    buf[k++] = '.';

    //skip spaces
    while(fatname[i] == ' ')
        i++;

    //copy extension
    for (; i < MSDOS_NAME && fatname[i] != ' '; ++i, ++k)
    {
        buf[k] = fatname[i];
    }

    buf[k] = '\0';
}

uint16_t find_cluster_by_name(int fat_fd, char *filename)
{
    uint32_t root_dir_block_offset = find_root_dir_block_offset(fat_fd);
    uint16_t bytes_per_sector = 512;  // Замените на фактическое значение
    size_t cluster = 0;

    uint8_t buf[MSDOS_NAME + 1] = "";
    uint8_t buffer[SECTOR_SIZE];
    if (read_block(fat_fd, root_dir_block_offset, buffer, SECTOR_SIZE) < 0)
        return -1;

    struct msdos_dir_entry entry;
    do {
        memcpy(&entry, buffer + cluster * sizeof(struct msdos_dir_entry), sizeof(struct msdos_dir_entry));

        // skip removed and LFN
        if (entry.name[0] == 0xE5 || entry.attr == 0x0F)
            continue;

        convert_fat_name(entry.name, buf);

        /* Unix only. */
        if (strcasecmp(filename, (char *)buf) == 0)
            return entry.start;
    } while (++cluster && entry.name[0] != 0x00);

    return 0;
}

void list_files(int fat_fd)
{
    uint32_t root_dir_block_offset = find_root_dir_block_offset(fat_fd);
    size_t cluster = 0;
    struct msdos_dir_entry entry;
    uint8_t buf[MSDOS_NAME + 1] = "";

    uint8_t buffer[SECTOR_SIZE];
    if (read_block(fat_fd, root_dir_block_offset, buffer, SECTOR_SIZE) < 0)
        return;

    do {
        memcpy(&entry, buffer + cluster * sizeof(struct msdos_dir_entry), sizeof(struct msdos_dir_entry));

        /* Skip removed and LFN. */
        if (entry.name[0] == 0xE5 || entry.attr == 0x0F)
            continue;

        convert_fat_name(entry.name, buf);

        printf("file: %s, %u\n", buf, entry.start);
    } while (++cluster && entry.name[0] != 0x00);
}

void print_file_data(int fat_fd, char *filename)
{
    uint16_t file_start = find_cluster_by_name(fat_fd,filename);
    if (file_start <= 0)
    {
        fprintf(stderr, "Failed to find cluster for file %s\n", filename);
        return;
    }

    uint32_t data_blk_offs = find_data_block_offset(fat_fd);
    uint32_t FAT_blk_offset = find_FAT_block_offset(fat_fd);
    uint8_t buf[SECTOR_SIZE * 4 + 1];
    uint8_t buffer[SECTOR_SIZE];
    read_block(fat_fd, FAT_blk_offset, buffer, SECTOR_SIZE);
    uint16_t next = file_start;

    while(next != 0xFFFF)
    {
        off_t offset = (data_blk_offs + (next - 2) * 4) * 512;
        pread(fat_fd, buf, 512 * 4, offset);
        buf[SECTOR_SIZE * 4] = '\0';
        printf("%s\n", buf);
        memcpy(&next, buffer + file_start * 2, 2);
        file_start = next;
    }
}
