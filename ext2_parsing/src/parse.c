#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

/* ext2 structures */
//---------------------------------------
#define EXT2_SUPER_MAGIC 0xEF53
#define EXT2_ROOT_INO 2
#define EXT2_NDIR_BLOCKS 12
#define EXT2_GOOD_OLD_INODE_SIZE 128

struct ext2_super_block
{
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    int16_t  s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    char     s_volume_name[16];
    char     s_last_mounted[64];
} __attribute__((packed));

struct ext2_group_desc
{
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t  bg_reserved[12];
} __attribute__((packed));

struct ext2_inode
{
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
} __attribute__((packed));

struct ext2_dir_entry_2
{
    uint32_t inode;
    uint16_t rec_len;
    uint8_t  name_len;
    uint8_t  file_type;
    char     name[];
} __attribute__((packed));

#define EXT2_SUPER_OFFSET 1024
//---------------------------------------

static ssize_t pread_full(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t got = 0;
    while ((size_t)got < count)
    {
        ssize_t r = pread(fd, (char *)buf + got, count - got, offset + got);
        if (r < 0)
            return r;
        if (r == 0)
            break;
        got += r;
    }
    return got;
}

static int read_superblock(int fd, struct ext2_super_block *sb)
{
    ssize_t r = pread_full(fd, sb, sizeof(*sb), EXT2_SUPER_OFFSET);
    if (r != sizeof(*sb))
    {
        fprintf(stderr, "failed to read superblock: %s\n", strerror(errno));
        return -1;
    }
    if (sb->s_magic != EXT2_SUPER_MAGIC)
    {
        fprintf(stderr, "not an ext2 filesystem (magic=0x%X)\n", sb->s_magic);
        return -1;
    }
    return 0;
}

static uint32_t block_size_from_sb(const struct ext2_super_block *sb)
{
    return 1024U << sb->s_log_block_size;
}

static int read_group_desc(int fd, const struct ext2_super_block *sb, struct ext2_group_desc *gd)
{
    uint32_t block_size = block_size_from_sb(sb);
    uint32_t superblock_block = EXT2_SUPER_OFFSET / block_size;
    off_t gd_offset = (off_t)(superblock_block + 1) * block_size;

    ssize_t r = pread_full(fd, gd, sizeof(*gd), gd_offset);
    if (r != sizeof(*gd))
    {
        fprintf(stderr, "failed to read group descriptor: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int read_inode(int fd, const struct ext2_super_block *sb, const struct ext2_group_desc *gd, unsigned int inode_no, struct ext2_inode *inode)
{
    uint32_t block_size = block_size_from_sb(sb);
    unsigned int inodes_per_group = sb->s_inodes_per_group;
    unsigned int index = inode_no - 1; /* inodes are 1-based */

    unsigned int inode_size = (sb->s_rev_level == 0) ? EXT2_GOOD_OLD_INODE_SIZE : sb->s_inode_size;
    off_t inode_table_block = gd->bg_inode_table;
    off_t inode_offset = (off_t)inode_table_block * block_size + (off_t)index * inode_size;

    ssize_t r = pread_full(fd, inode, sizeof(*inode), inode_offset);
    if (r != sizeof(*inode))
    {
        fprintf(stderr, "failed to read inode %u: %s\n", inode_no, strerror(errno));
        return -1;
    }
    return 0;
}

void print_ext2_info(int fd)
{
    struct ext2_super_block sb;
    if (read_superblock(fd, &sb) < 0)
        return;

    uint32_t block_size = block_size_from_sb(&sb);

    printf("EXT2 INFO\n");
    printf("  Inodes count: %u\n", sb.s_inodes_count);
    printf("  Blocks count: %u\n", sb.s_blocks_count);
    printf("  Free blocks: %u\n", sb.s_free_blocks_count);
    printf("  Free inodes: %u\n", sb.s_free_inodes_count);
    printf("  First data block: %u\n", sb.s_first_data_block);
    printf("  Block size: %u\n", block_size);
    printf("  Blocks per group: %u\n", sb.s_blocks_per_group);
    printf("  Inodes per group: %u\n", sb.s_inodes_per_group);
    printf("  Magic: 0x%X\n", sb.s_magic);
}

static void print_dir_entries_in_block(int fd, uint32_t block_num, uint32_t block_size)
{
    uint8_t *buf = malloc(block_size);
    if (!buf)
        return;
    off_t off = (off_t)block_num * block_size;
    if (pread_full(fd, buf, block_size, off) != (ssize_t)block_size)
    {
        free(buf);
        return;
    }

    uint32_t pos = 0;
    while (pos < block_size)
    {
        struct ext2_dir_entry_2 *de = (struct ext2_dir_entry_2 *)(buf + pos);
        if (de->inode == 0)
            break;
        char name[256] = {0};
        unsigned int namelen = de->name_len;
        if (namelen > sizeof(name)-1)
            namelen = sizeof(name)-1;
        memcpy(name, de->name, namelen);
        name[namelen] = '\0';

        printf("  %s (inode %u, type %u)\n", name, de->inode, de->file_type);

        /* avoid infinite loop */
        if (de->rec_len == 0)
            break;
        pos += de->rec_len;
    }

    free(buf);
}

void list_root_dir(int fd)
{
    struct ext2_super_block sb;
    if (read_superblock(fd, &sb) < 0)
        return;

    struct ext2_group_desc gd;
    if (read_group_desc(fd, &sb, &gd) < 0)
        return;

    struct ext2_inode root_inode;
    if (read_inode(fd, &sb, &gd, EXT2_ROOT_INO, &root_inode) < 0)
        return;

    uint32_t block_size = block_size_from_sb(&sb);

    printf("Root directory entries:\n");
    for (int i = 0; i < EXT2_NDIR_BLOCKS; ++i)
    {
        uint32_t b = root_inode.i_block[i];
        if (b == 0) continue;
        print_dir_entries_in_block(fd, b, block_size);
    }
}

static unsigned int find_inode_in_dir_by_name(int fd, const struct ext2_super_block *sb, const struct ext2_inode *dir_inode, const char *name)
{
    uint32_t block_size = block_size_from_sb(sb);
    for (int i = 0; i < EXT2_NDIR_BLOCKS; ++i)
    {
        uint32_t b = dir_inode->i_block[i];
        if (b == 0)
            continue;

        uint8_t *buf = malloc(block_size);
        if (!buf)
            return 0;

        off_t off = (off_t)b * block_size;
        if (pread_full(fd, buf, block_size, off) != (ssize_t)block_size)
        {
            free(buf);
            return 0;
        }

        uint32_t pos = 0;
        while (pos < block_size)
        {
            struct ext2_dir_entry_2 *de = (struct ext2_dir_entry_2 *)(buf + pos);
            if (de->inode == 0)
                break;

            char fname[256] = {0};
            unsigned int namelen = de->name_len;
            if (namelen > sizeof(fname)-1)
                namelen = sizeof(fname) - 1;

            memcpy(fname, de->name, namelen);
            fname[namelen] = '\0';

            if (strcmp(fname, name) == 0)
            {
                unsigned int inode_num = de->inode;
                free(buf);
                return inode_num;
            }

            if (de->rec_len == 0)
                break;
            pos += de->rec_len;
        }
        free(buf);
    }

    return 0;
}

int print_file_data_by_name(int fd, const char *name)
{
    struct ext2_super_block sb;
    if (read_superblock(fd, &sb) < 0)
        return -1;

    struct ext2_group_desc gd;
    if (read_group_desc(fd, &sb, &gd) < 0)
        return -1;

    struct ext2_inode root_inode;
    if (read_inode(fd, &sb, &gd, EXT2_ROOT_INO, &root_inode) < 0)
        return -1;

    unsigned int inode_no = find_inode_in_dir_by_name(fd, &sb, &root_inode, name);
    if (inode_no == 0)
    {
        fprintf(stderr, "file '%s' not found in root directory\n", name);
        return -1;
    }

    struct ext2_inode inode;
    if (read_inode(fd, &sb, &gd, inode_no, &inode) < 0)
        return -1;

    uint32_t block_size = block_size_from_sb(&sb);
    uint64_t size = inode.i_size; /* supports large regular files */
    uint64_t printed = 0;

    uint8_t *data_buf = malloc(block_size);
    if (!data_buf)
        return -1;

    /* Helper to output one data block respecting file size */
    #define OUTPUT_BLOCK(block_num) do {                                                            \
        if ((block_num) == 0 || printed >= size) break;                                             \
        off_t off_ = (off_t)(block_num) * block_size;                                               \
        ssize_t r_ = pread_full(fd, data_buf, block_size, off_);                                    \
        if (r_ <= 0) break;                                                                         \
        size_t to_write_ = (size - printed > (uint64_t)r_) ? (size_t)r_ : (size_t)(size - printed); \
        fwrite(data_buf, 1, to_write_, stdout);                                                     \
        printed += to_write_;                                                                       \
    } while(0)

    /* direct blocks */
    for (int i = 0; i < EXT2_NDIR_BLOCKS && printed < size; ++i)
    {
        OUTPUT_BLOCK(inode.i_block[i]);
    }

    /* end if no indirect blocks needed*/
    if (printed >= size)
    {
        free(data_buf);
        printf("\n");
        return 0;
    }

    uint32_t ptrs_per_block = block_size / sizeof(uint32_t);
    uint32_t *ptr_buf = malloc(block_size);
    if (!ptr_buf)
    {
        free(data_buf);
        return -1;
    }

    /* single indirect */
    if (inode.i_block[EXT2_NDIR_BLOCKS] && printed < size)
    {
        off_t off = (off_t)inode.i_block[EXT2_NDIR_BLOCKS] * block_size;
        if (pread_full(fd, ptr_buf, block_size, off) == (ssize_t)block_size)
        {
            for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
            {
                uint32_t b = ptr_buf[i];
                if (b == 0)
                    continue; /* sparse */
                OUTPUT_BLOCK(b);
            }
        }
    }

    /* double indirect */
    if (inode.i_block[EXT2_NDIR_BLOCKS + 1] && printed < size)
    {
        off_t off_dind = (off_t)inode.i_block[EXT2_NDIR_BLOCKS + 1] * block_size;
        if (pread_full(fd, ptr_buf, block_size, off_dind) == (ssize_t)block_size)
        {
            for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
            {
                uint32_t indir_blk = ptr_buf[i];
                if (!indir_blk)
                    continue;
                off_t off_indir = (off_t)indir_blk * block_size;
                uint32_t *lvl1 = malloc(block_size);
                if (!lvl1)
                {
                    free(ptr_buf);
                    free(data_buf);
                    return -1;
                }
                if (pread_full(fd, lvl1, block_size, off_indir) == (ssize_t)block_size)
                {
                    for (uint32_t j = 0; j < ptrs_per_block && printed < size; ++j)
                    {
                        uint32_t b = lvl1[j];
                        if (b == 0)
                            continue;
                        OUTPUT_BLOCK(b);
                    }
                }
                free(lvl1);
            }
        }
    }

    /* triple indirect */
    if (inode.i_block[EXT2_NDIR_BLOCKS + 2] && printed < size)
    {
        off_t off_tind = (off_t)inode.i_block[EXT2_NDIR_BLOCKS + 2] * block_size;
        if (pread_full(fd, ptr_buf, block_size, off_tind) == (ssize_t)block_size)
        {
            for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
            {
                uint32_t dind_blk = ptr_buf[i];
                if (!dind_blk)
                    continue;

                uint32_t *lvl2 = malloc(block_size);
                if (!lvl2)
                {
                    free(ptr_buf);
                    free(data_buf);
                    return -1;
                }

                if (pread_full(fd, lvl2, block_size, (off_t)dind_blk * block_size) == (ssize_t)block_size)
                {
                    for (uint32_t j = 0; j < ptrs_per_block && printed < size; ++j)
                    {
                        uint32_t indir_blk = lvl2[j];
                        if (!indir_blk)
                            continue;
                        uint32_t *lvl1 = malloc(block_size);
                        if (!lvl1)
                        {
                            free(lvl2);
                            free(ptr_buf);
                            free(data_buf);
                            return -1;
                        }
                        if (pread_full(fd, lvl1, block_size, (off_t)indir_blk * block_size) == (ssize_t)block_size)
                        {
                            for (uint32_t k = 0; k < ptrs_per_block && printed < size; ++k)
                            {
                                uint32_t b = lvl1[k];
                                if (!b)
                                    continue;
                                OUTPUT_BLOCK(b);
                            }
                        }
                        free(lvl1);
                    }
                }
                free(lvl2);
            }
        }
    }

    free(ptr_buf);
    free(data_buf);
    printf("\n");
    return 0;
}

/* Resolve a full path like /dir1/dir2/file.txt */
static int resolve_path_to_inode(int fd, struct ext2_super_block *sb, struct ext2_group_desc *gd, const char *path, unsigned int *out_inode)
{
    if (!path || !out_inode)
        return -1;

    /* Skip leading '/' */
    while (*path == '/')
        path++;
    if (*path == '\0')
    {
        *out_inode = EXT2_ROOT_INO;
        return 0;
    }

    unsigned int current = EXT2_ROOT_INO;
    char component[256];
    const char *p = path;
    while (*p)
    {
        size_t len = 0;
        while (p[len] && p[len] != '/')
        {
            if (len < sizeof(component)-1) component[len] = p[len];
            len++;
        }

        /* skip duplicate slashes */
        if (len == 0)
        {
            p += 1;
            continue;
        }
        if (len >= sizeof(component))
            return -1; /* name too long */
        component[len] = '\0';

        /* read cur inode */
        struct ext2_inode dir_inode;
        if (read_inode(fd, sb, gd, current, &dir_inode) < 0)
            return -1;

        /* find next */
        unsigned int next = find_inode_in_dir_by_name(fd, sb, &dir_inode, component);
        if (next == 0)
            return -1; /* not found */

        current = next;
        p += len;
        if (*p == '/')
            p++;
    }
    *out_inode = current;
    return 0;
}

int print_file_data_by_path(int fd, const char *path)
{
    struct ext2_super_block sb;
    if (read_superblock(fd, &sb) < 0)
        return -1;
    struct ext2_group_desc gd;
    if (read_group_desc(fd, &sb, &gd) < 0)
        return -1;

    unsigned int inode_no = 0;
    if (resolve_path_to_inode(fd, &sb, &gd, path, &inode_no) < 0)
    {
        fprintf(stderr, "path '%s' not found\n", path);
        return -1;
    }

    struct ext2_inode inode;
    if (read_inode(fd, &sb, &gd, inode_no, &inode) < 0)
        return -1;

    /* If inode is dir, just list entries */
    if ((inode.i_mode & S_IFDIR) != 0)
    {
        printf("Listing directory '%s':\n", path);
        uint32_t block_size = block_size_from_sb(&sb);
        for (int i = 0; i < EXT2_NDIR_BLOCKS; ++i)
        {
            uint32_t b = inode.i_block[i];
            if (!b)
                continue;

            uint8_t *buf = malloc(block_size);
            if (!buf)
                continue;

            if (pread_full(fd, buf, block_size, (off_t)b * block_size) != (ssize_t)block_size)
            {
                free(buf);
                continue;
            }

            uint32_t pos = 0;
            while (pos < block_size)
            {
                struct ext2_dir_entry_2 *de = (struct ext2_dir_entry_2 *)(buf + pos);
                if (de->inode == 0 || de->rec_len == 0)
                    break;

                unsigned int namelen = de->name_len;
                if (namelen == 0 || namelen > 255)
                {
                    pos += de->rec_len;
                    continue;
                }
                char name[256];
                memcpy(name, de->name, namelen);
                name[namelen] = '\0';
                printf("  %s (inode %u, type %u)\n", name, de->inode, de->file_type);
                pos += de->rec_len;
            }
            free(buf);
        }
        return 0;
    }

    if (!strchr(path, '/'))
        return print_file_data_by_name(fd, path);

    uint32_t block_size = 1024U << sb.s_log_block_size;
    uint64_t size = inode.i_size;
    uint64_t printed = 0;
    uint8_t *data_buf = malloc(block_size);
    if (!data_buf)
        return -1;

    #define OUTPUT_BLOCK_LOCAL(block_num) do { \
        if ((block_num) == 0 || printed >= size) break; \
        off_t off_ = (off_t)(block_num) * block_size; \
        ssize_t r_ = pread_full(fd, data_buf, block_size, off_); \
        if (r_ <= 0) break; \
        size_t to_write_ = (size - printed > (uint64_t)r_) ? (size_t)r_ : (size_t)(size - printed); \
        fwrite(data_buf, 1, to_write_, stdout); \
        printed += to_write_; \
    } while(0)

    for (int i = 0; i < EXT2_NDIR_BLOCKS && printed < size; ++i)
    {
        OUTPUT_BLOCK_LOCAL(inode.i_block[i]);
    }

    if (printed < size) {
        uint32_t ptrs_per_block = block_size / sizeof(uint32_t);
        uint32_t *ptr_buf = malloc(block_size);
        if (!ptr_buf)
        {
            free(data_buf);
            return -1;
        }

        /* single */
        if (inode.i_block[EXT2_NDIR_BLOCKS] && printed < size)
        {
            if (pread_full(fd, ptr_buf, block_size, (off_t)inode.i_block[EXT2_NDIR_BLOCKS] * block_size) == (ssize_t)block_size)
                for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
                    OUTPUT_BLOCK_LOCAL(ptr_buf[i]);
        }

        /* double */
        if (inode.i_block[EXT2_NDIR_BLOCKS + 1] && printed < size)
        {
            if (pread_full(fd, ptr_buf, block_size, (off_t)inode.i_block[EXT2_NDIR_BLOCKS + 1] * block_size) == (ssize_t)block_size)
            {
                for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
                {
                    uint32_t lvl1_blk = ptr_buf[i];
                    if (!lvl1_blk)
                        continue;

                    uint32_t *lvl1 = malloc(block_size);
                    if (!lvl1)
                    {
                        free(ptr_buf);
                        free(data_buf);
                        return -1;
                    }

                    if (pread_full(fd, lvl1, block_size, (off_t)lvl1_blk * block_size) == (ssize_t)block_size)
                        for (uint32_t j = 0; j < ptrs_per_block && printed < size; ++j)
                            OUTPUT_BLOCK_LOCAL(lvl1[j]);
                    free(lvl1);
                }
            }
        }

        /* triple */
        if (inode.i_block[EXT2_NDIR_BLOCKS + 2] && printed < size)
        {
            if (pread_full(fd, ptr_buf, block_size, (off_t)inode.i_block[EXT2_NDIR_BLOCKS + 2] * block_size) == (ssize_t)block_size)
            {
                for (uint32_t i = 0; i < ptrs_per_block && printed < size; ++i)
                {
                    uint32_t dind_blk = ptr_buf[i];
                    if (!dind_blk)
                        continue;

                    uint32_t *lvl2 = malloc(block_size);
                    if (!lvl2)
                    {
                        free(ptr_buf);
                        free(data_buf);
                        return -1;
                    }

                    if (pread_full(fd, lvl2, block_size, (off_t)dind_blk * block_size) == (ssize_t)block_size)
                    {
                        for (uint32_t j = 0; j < ptrs_per_block && printed < size; ++j)
                        {
                            uint32_t indir_blk = lvl2[j];
                            if (!indir_blk)
                                continue;
                            uint32_t *lvl1 = malloc(block_size);
                            if (!lvl1)
                            {
                                free(lvl2);
                                free(ptr_buf);
                                free(data_buf);
                                return -1;
                            }
                            if (pread_full(fd, lvl1, block_size, (off_t)indir_blk * block_size) == (ssize_t)block_size)
                                for (uint32_t k = 0; k < ptrs_per_block && printed < size; ++k)
                                    OUTPUT_BLOCK_LOCAL(lvl1[k]);
                            free(lvl1);
                        }
                    }
                    free(lvl2);
                }
            }
        }
        free(ptr_buf);
    }

    free(data_buf);
    printf("\n");
    return 0;
}
