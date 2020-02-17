#ifndef _FAT_SHELL_H_
#define _FAT_SHELL_H_
#define FSOPRS_TO_EXT2FS( a )      ( EXT2_FILESYSTEM* )a->pdata
#include "ext2.h"
#include "shell.h"

// void printFromP2P(char * start, char * end);
// void dump_block(DISK_OPERATIONS * disk, EXT2_SUPER_BLOCK *sb, int num);

void shell_register_filesystem( SHELL_FILESYSTEM* );
int shell_entry_to_ext2_entry(const SHELL_ENTRY* shell_entry, EXT2_NODE* fat_entry);
int ext2_entry_to_shell_entry(EXT2_FILESYSTEM* fs, const EXT2_NODE* ext2_entry, SHELL_ENTRY* shell_entry);

int fs_write( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, unsigned long offset, unsigned long length, const char* buffer );
int	fs_create(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry);
int	fs_remove(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name);
int fs_lookup(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, const char* name);
int fs_read_dir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY_LIST* list);
int fs_mkdir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry);
int fs_rmdir( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name);
int fs_format(DISK_OPERATIONS* disk, void* param);
#endif
