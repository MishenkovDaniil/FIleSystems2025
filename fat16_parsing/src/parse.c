#include <linux/msdos_fs.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <strings.h>
#include <assert.h>

static const char *ATTRS[] = {
    [0] = "read-only",
    [1] = "hidden",
    [2] = "system",
    [3] = "volume label",
    [4] = "subdirectory",
    [5] = "archive"
};

static void print_file_attrs(uint8_t attrs)
{
    printf("  File attributes: ");
    for (int i = 0; i < 6; ++i)
    {
        if (attrs & (1 << i))
            printf("%s ", ATTRS[i]);
    }
    printf("\n");
}
static void print_file_times(struct msdos_dir_entry *entry)
{
    uint16_t ctime = entry->ctime;
    uint16_t cdate = entry->cdate;
    uint16_t adate = entry->adate;

    uint16_t cyear = (cdate >> 9) + 1980;
    uint8_t cmonth = (cdate >> 5) & 0x0F;
    uint8_t cday = cdate & 0x1F;

    uint8_t chour = (ctime >> 11) & 0x1F;
    uint8_t cmin = (ctime >> 5) & 0x3F;
    uint8_t csec = (ctime & 0x1F) * 2;

    uint16_t ayear = (adate >> 9) + 1980;
    uint8_t amonth = (adate >> 5) & 0x0F;
    uint8_t aday = adate & 0x1F;

    printf("  Creation date: %02u/%02u/%04u\n", cday, cmonth, cyear);
    printf("  Creation time: %02u:%02u:%02u\n", chour, cmin, csec);
    printf("  Last access date: %02u/%02u/%04u\n", aday, amonth, ayear);
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

static void print_fat_file_info(struct msdos_dir_entry *entry)
{
    uint8_t buf[MSDOS_NAME + 1] = "";
    convert_fat_name(entry->name, buf);

    printf("%s\n", buf);
    print_file_attrs(entry->attr);
    print_file_times(entry);
    printf("\n");
}

static int get_fat_bs(int fat_fd, struct fat_boot_sector *fat_bs)
{
    if (pread(fat_fd, fat_bs, sizeof(struct fat_boot_sector), 0) < 0)
    {
        fprintf(stderr, "ERROR: failed to read from image, fd = %d, err = %s\n", fat_fd, strerror(errno));
        return -1;
    }
    return 0;
}

void print_fat_info(int fd)
{
    struct fat_boot_sector buf;

    if (get_fat_bs(fd, &buf) < 0)
        return;

    uint16_t sector_size = buf.sector_size[0] | (buf.sector_size[1] << 8);
    uint16_t dir_entries = buf.dir_entries[0] | (buf.dir_entries[1] << 8);
    uint16_t sectors = buf.sectors[0] | (buf.sectors[1] << 8);

    printf(
        "FAT-16 INFO\n"
        "\tsystem_id: %.8s\n"
        "\tsector_size: %u bytes\n"
        "\tsec_per_clus: %u\n"
        "\treserved: %u\n"
        "\tfats: %u\n"
        "\tdir_entries: %u\n"
        "\tsectors: %u\n"
        "\tmedia: 0x%02X\n"
        "\tfat_length: %u sectors\n"
        "\tsecs_track: %u\n"
        "\theads: %u\n"
        "\thidden: %u\n"
        "\ttotal_sect: %u\n",
        buf.system_id,
        sector_size,
        buf.sec_per_clus,
        buf.reserved,
        buf.fats,
        dir_entries,
        sectors,
        buf.media,
        buf.fat_length,
        buf.secs_track,
        buf.heads,
        buf.hidden,
        buf.total_sect
    );
}

inline static uint32_t get_root_dir_addr(struct fat_boot_sector *fat_bs)
{
    assert(fat_bs);

    return fat_bs->reserved + (fat_bs->fats * fat_bs->fat_length);
}

inline static uint32_t get_FAT_addr(struct fat_boot_sector *fat_bs)
{
    assert(fat_bs);

    return fat_bs->reserved;
}

uint32_t static get_data_area_addr(struct fat_boot_sector *fat_bs)
{
    assert(fat_bs);

    uint16_t dir_entries = fat_bs->dir_entries[0] | (fat_bs->dir_entries[1] << 8);
    uint16_t bytes_per_sector = fat_bs->sector_size[0] | (fat_bs->sector_size[1] << 8);
    uint16_t root_dir_sectors = (dir_entries * 32 + bytes_per_sector - 1) / bytes_per_sector;
    return fat_bs->reserved + (fat_bs->fats * fat_bs->fat_length) + root_dir_sectors;
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

static uint16_t find_cluster_by_name(int fat_fd, char *filename, struct fat_boot_sector *fat_bs)
{
    assert(fat_bs);
    if (get_fat_bs(fat_fd, fat_bs) < 0)
        return 0;

    uint32_t root_dir_block_offset = get_root_dir_addr(fat_bs);
    const uint32_t sector_size = fat_bs->sector_size[0] | (fat_bs->sector_size[1] << 8);
    uint16_t bytes_per_sector = fat_bs->sector_size[0] | (fat_bs->sector_size[1] << 8);
    size_t cluster = 0;

    uint8_t buf[MSDOS_NAME + 1] = "";
    uint8_t buffer[sector_size];
    if (read_block(fat_fd, root_dir_block_offset, buffer, sector_size) < 0)
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
    struct fat_boot_sector fat_bs;
    if (get_fat_bs(fat_fd, &fat_bs) < 0)
        return;

    const uint32_t sector_size = fat_bs.sector_size[0] | (fat_bs.sector_size[1] << 8);
    const uint32_t root_dir_block_offset = get_root_dir_addr(&fat_bs);

    uint8_t buffer[sector_size];
    if (read_block(fat_fd, root_dir_block_offset, buffer, sector_size) < 0)
        return;

    size_t cluster = 0;
    uint8_t buf[MSDOS_NAME + 1] = "";
    struct msdos_dir_entry entry;
    do {
        memcpy(&entry, buffer + cluster * sizeof(struct msdos_dir_entry), sizeof(struct msdos_dir_entry));

        /* Skip removed and LFN. */
        if (entry.name[0] == 0xE5 || entry.attr == 0x0F)
            continue;
        if (entry.name[0] == 0x00)
            break;

        print_fat_file_info(&entry);
    } while (++cluster);
}

void print_file_data(int fat_fd, char *filename)
{
    struct fat_boot_sector fat_bs;
    if (get_fat_bs(fat_fd, &fat_bs) < 0)
        return;

    uint16_t file_start = find_cluster_by_name(fat_fd, filename, &fat_bs);
    if (file_start <= 0)
    {
        fprintf(stderr, "Failed to find cluster for file %s\n", filename);
        return;
    }

    const uint32_t data_blk_offs = get_data_area_addr(&fat_bs);
    const uint32_t sector_size = fat_bs.sector_size[0] | (fat_bs.sector_size[1] << 8);
    const uint32_t cluster_size = fat_bs.sec_per_clus * sector_size;
    uint8_t buf[cluster_size + 1];
    uint8_t buffer[sector_size];

    const uint32_t FAT_blk_offset = get_FAT_addr(&fat_bs);
    read_block(fat_fd, FAT_blk_offset, buffer, sector_size);

    printf("%s content:\n", filename);
    uint16_t next = file_start;
    while(next != 0xFFFF)
    {
        off_t offset = (data_blk_offs + (next - 2) * fat_bs.sec_per_clus) * sector_size;
        pread(fat_fd, buf, sector_size * fat_bs.sec_per_clus, offset);
        buf[cluster_size] = '\0';

        printf("%s", buf);
        memcpy(&next, buffer + file_start * 2, 2);
        file_start = next;
    }
    printf("\n");
}
