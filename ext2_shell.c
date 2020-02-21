#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "ext2_shell.h"
typedef struct {
	char * address;
}DISK_MEMORY;

int fs_format(DISK_OPERATIONS* disk, void* param)
{
	printf("formatting as a %s\n", (char *)param);

	return ext2_format(disk);
}

static SHELL_FILE_OPERATIONS g_file =
{
	fs_create,
	fs_remove,
	fs_read,
	fs_write
};

static SHELL_FS_OPERATIONS   g_fsOprs =
{
	fs_read_dir,
	fs_stat,
	fs_mkdir,
	fs_rmdir,
	fs_lookup,
	&g_file,
	NULL
};

int fs_mount(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, SHELL_ENTRY* root)
{
	EXT2_FILESYSTEM* fs;
	EXT2_NODE ext2_entry;
	int result;
	UINT32 number_of_group;

	*fsOprs = g_fsOprs;

	fsOprs->pdata = malloc(sizeof(EXT2_FILESYSTEM));
	fs = FSOPRS_TO_EXT2FS(fsOprs);
	ZeroMemory(fs, sizeof(EXT2_FILESYSTEM));
	fs->disk = disk;

	result = ext2_read_superblock(fs, &ext2_entry);
	number_of_group = disk->number_of_sectors / (fs->sb.sector_per_block * fs->sb.block_per_group);

	if (result == EXT2_SUCCESS)
	{
		printf("number of groups               : %d\n", number_of_group);
		printf("blocks per group               : %d\n", fs->sb.block_per_group);
		printf("bytes per block                : %d\n", disk->bytes_per_sector);
		printf("free block count               : %d\n", fs->sb.free_block_count);
		printf("free inode count               : %d\n", fs->sb.free_inode_count);
		printf("first non reserved inode       : %d\n", fs->sb.first_ino);
		printf("inode structure size           : %d\n", fs->sb.inode_size);
		printf("first data block number        : %d\n", fs->sb.first_meta_bg);
		printf("\n----------------------------------------------\n");
	}

	printf("%s ", ext2_entry.entry.name);
	ext2_entry_to_shell_entry(fs, &ext2_entry, root);

	EXT2_NODE *debug = (EXT2_NODE *)root->pdata;

	return result;
}

void fs_umount(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs)
{
	// fsOprs -> pdata : FAT_FILESYSTEM
	if( fsOprs && fsOprs->pdata ) // 마운트된 경우
	{
		// 1. 파일 시스템 언마운트
		// ext2_umount( (EXT2_FILESYSTEM *)fsOprs->pdata );

		// 2. pdata 할당 해제
		free( fsOprs->pdata );
		fsOprs->pdata = 0;
	}
}

static SHELL_FILESYSTEM g_fat =
{
	"EXT2",
	fs_mount,
	fs_umount,
	fs_format
};

int adder(EXT2_FILESYSTEM* fs, void* list, EXT2_NODE* entry)
{
	SHELL_ENTRY_LIST*   entryList = (SHELL_ENTRY_LIST*)list;
	SHELL_ENTRY         newEntry;

	ext2_entry_to_shell_entry(fs, entry, &newEntry);
	add_entry_list(entryList, &newEntry);

	return EXT2_SUCCESS;
}

int fs_read(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, unsigned long offset, unsigned long length, const char* buffer)
{
	EXT2_NODE EXT2Entry;

	shell_entry_to_ext2_entry(entry, &EXT2Entry);

	return ext2_read(&EXT2Entry, offset, length, buffer);
}

int fs_write(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, unsigned long offset, unsigned long length, const char* buffer)
{
	EXT2_NODE EXT2Entry;

	shell_entry_to_ext2_entry(entry, &EXT2Entry);

	return ext2_write(&EXT2Entry, offset, length, buffer);
}

void shell_register_filesystem(SHELL_FILESYSTEM* fs)
{
	*fs = g_fat;
}

int	fs_create(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry)
{
	EXT2_NODE	EXT2Parent;
	EXT2_NODE	EXT2Entry;
	int				result;

	shell_entry_to_ext2_entry(parent, &EXT2Parent);

	result = ext2_create(&EXT2Parent, name, &EXT2Entry);

	ext2_entry_to_shell_entry(EXT2Parent.fs, &EXT2Entry, retEntry);

	return result;
}

int	fs_remove(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name)
{
	EXT2_NODE EXT2Parent;
	EXT2_NODE file;

	shell_entry_to_ext2_entry(parent, &EXT2Parent);
	if (ext2_lookup(&EXT2Parent, name, &file) == EXT2_ERROR)
		return EXT2_ERROR;
		
	return ext2_remove(&file);
}

int shell_entry_to_ext2_entry(const SHELL_ENTRY* shell_entry, EXT2_NODE* fat_entry)
{
	EXT2_NODE* entry = (EXT2_NODE*)shell_entry->pdata;


	*fat_entry = *entry;

	return EXT2_SUCCESS;
}

int ext2_entry_to_shell_entry(EXT2_FILESYSTEM* fs, const EXT2_NODE* ext2_entry, SHELL_ENTRY* shell_entry)
{
	EXT2_NODE* entry = (EXT2_NODE*)shell_entry->pdata;
	INODE inodeBuffer;
	BYTE* str = "/";
	int inode = ext2_entry->entry.inode;
	
	ZeroMemory(shell_entry, sizeof(SHELL_ENTRY));
	get_inode(fs, inode, &inodeBuffer);

	memcpy(shell_entry->name, ext2_entry->entry.name, ext2_entry->entry.name_len);
	shell_entry->name[ext2_entry->entry.name_len] = '\0';
	
	if (FILE_TYPE_DIR & inodeBuffer.mode)
		shell_entry->isDirectory = 1;
	else
		shell_entry->isDirectory = 0;

	shell_entry->size = inodeBuffer.size;

	*entry = *ext2_entry;

	return EXT2_SUCCESS;
}

int fs_lookup(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY* entry, const char* name)
{
	EXT2_NODE	EXT2Parent;
	EXT2_NODE	EXT2Entry;
	int				result;

	shell_entry_to_ext2_entry(parent, &EXT2Parent);

	if (result = ext2_lookup(&EXT2Parent, name, &EXT2Entry)) return result;

	ext2_entry_to_shell_entry(EXT2Parent.fs, &EXT2Entry, entry);

	return result;
}

int fs_read_dir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, SHELL_ENTRY_LIST* list)
{
	EXT2_NODE   entry;

	if (list->count)
		release_entry_list(list);

	shell_entry_to_ext2_entry(parent, &entry);
	ext2_read_dir(&entry, adder, list);
	
	return EXT2_SUCCESS;
}

int fs_stat( DISK_OPERATIONS* disk, struct SHELL_FS_OPERATIONS* fsOprs, unsigned int* total_sectors, unsigned int* used_sectors)
{
	EXT2_NODE entry;

	return ext2_df( fsOprs->pdata, total_sectors, used_sectors);
}


int is_exist(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name)
{
	SHELL_ENTRY_LIST      list;
	SHELL_ENTRY_LIST_ITEM*   current;

	init_entry_list(&list);

	fs_read_dir(disk, fsOprs, parent, &list);
	current = list.first;

	while (current)
	{
		if (strcmp((char*)current->entry.name, name) == 0)
		{
			release_entry_list(&list);
			return EXT2_ERROR;
		}
		current = current->next;
	}

	release_entry_list(&list);
	return EXT2_SUCCESS;
}

int fs_mkdir(DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name, SHELL_ENTRY* retEntry)
{
	EXT2_FILESYSTEM* ext2;
	EXT2_NODE      EXT2_Parent;
	EXT2_NODE      EXT2_Entry;
	int               result;

	ext2 = (EXT2_FILESYSTEM*)fsOprs->pdata;

	if (is_exist(disk, fsOprs, parent, name)) {
		printf("error : %s already exist\n", name);
		return EXT2_ERROR;
	}

	shell_entry_to_ext2_entry(parent, &EXT2_Parent);

	result = ext2_mkdir(&EXT2_Parent, name, &EXT2_Entry);
	if (result == EXT2_ERROR) {
		printf("ext2_mkdir error\n");
	}

	ext2_entry_to_shell_entry(ext2, &EXT2_Entry, retEntry);

	return result;
}

int fs_rmdir( DISK_OPERATIONS* disk, SHELL_FS_OPERATIONS* fsOprs, const SHELL_ENTRY* parent, const char* name)
{
	EXT2_NODE EXT2Parent;
	EXT2_NODE dir;

	shell_entry_to_ext2_entry(parent, &EXT2Parent);
	if (ext2_lookup(&EXT2Parent, name, &dir) == EXT2_ERROR)
	{
		printf("can't find entry %s\n", name);
		return EXT2_ERROR;
	}
	
	return ext2_rmdir(&dir);
}