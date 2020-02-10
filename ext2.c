typedef struct
{
	char*	address;
} DISK_MEMORY;

#include "ext2.h"
#define MIN( a, b )					( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )					( ( a ) > ( b ) ? ( a ) : ( b ) )

int ext2_write(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	return 0;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs);

int ext2_format(DISK_OPERATIONS* disk, UINT32 log_block_size)
{
	EXT2_SUPER_BLOCK sb;
	EXT2_GROUP_DESCRIPTOR gd;
	EXT2_GROUP_DESCRIPTOR  gd_another_group;
	
    // super block setting 전에는 한 block을 1KB로 인지
    // const UINT32 format_sector_per_block = 2;
	
	int i, gi, j;
	const int BOOT_SECTOR_BASE = 1;
	// char block_format[MAX_SECTOR_SIZE * format_sector_per_block];

	// super block 채우기
	if (fill_super_block(&sb, disk->number_of_sectors, disk->bytes_per_sector, log_block_size) != EXT2_SUCCESS)
		return EXT2_ERROR;
	/*
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 block_per_group = byte_per_block << 3;
    const BYTE sector_per_block = byte_per_block / disk->bytes_per_sector;
    UINT32 number_of_group = disk->number_of_sectors / (sector_per_block * block_per_group);
	*/

	char block[MAX_SECTOR_SIZE * sb.sector_per_block];

	QWORD sector_num_per_group = sb.block_per_group * sb.sector_per_block;

	// disk에 super block write
	ZeroMemory(block, sizeof(block));
	memcpy(block, &sb, sizeof(sb));
    SECTOR sector_index = BOOT_SECTOR_BASE * sb.sector_per_block;
    for (int i = 0; i < sb.sector_per_block; i++) 
	{
        disk->write_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]);
    }
    // 끝

	// descriptor block 채우기 
	if (fill_descriptor_block(&gd, &sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;

    // descriptor block을 그룹 개수만큼 만들어서 써야함
    // superblock 다음위치
	// descriptor block을 disk에 쓰기 


	// block bitmap 채우기
	ZeroMemory((block), sizeof(block));
/*
	sector[0] = 0xff;
	sector[1] = 0xff;
	sector[2] = 0x01; 
*/
    SECTOR sector_index = (BOOT_SECTOR_BASE + 그룹 디스크립터 블록 개수에 따라 달라짐) * format_sector_per_block;
    for (int i = 0; i < format_sector_per_block; i++) {
        disk->write_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]);
    }
	// inode bitmap 채우기
	ZeroMemory(block, sizeof(block));

	sector[0] = 0xff; // 8개
	sector[1] = 0x03; // 2개  inode 예약 영역 10개 잡아줌

    SECTOR sector_index = (BOOT_SECTOR_BASE + 아이노드 비트맵 위치) * format_sector_per_block;
    for (int i = 0; i < format_sector_per_block; i++) {
        disk->write_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]);
    }

	// inode table
	ZeroMemory(block), sizeof(block));

    /*
	for (i = 4; i < sb.first_data_block_each_group; i++)
		disk->write_sector(disk, BOOT_SECTOR_BASE + i, sector);

	for (gi = 1; gi < NUMBER_OF_GROUPS; gi++)
	{
		sb.block_group_number = gi;

		ZeroMemory(sector, sizeof(sector));
		memcpy(sector, &sb, sizeof(sb));

		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE, sector);

		ZeroMemory(sector, sizeof(sector));
		for (j = 0; j < NUMBER_OF_GROUPS; j++)
		{
			memcpy(sector + j * sizeof(gd), &gd, sizeof(gd));
		}
		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 1, sector);

		// block bitmap
		ZeroMemory(sector, sizeof(sector));
		sector[0] = 0xff;
		sector[1] = 0xff;
		sector[2] = 0x01;
		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 2, sector);

		//inode bitmap
		ZeroMemory(sector, sizeof(sector));

		disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + 3, sector);

		// inode table
		ZeroMemory(sector, sizeof(sector));
		for (i = 4; i < sb.first_data_block_each_group; i++)
			disk->write_sector(disk, sector_num_per_group * gi + BOOT_SECTOR_BASE + i, sector);
	}
    */

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode structure   : %u\n", sb.inode_structure_size);
	PRINTF("block byte size                : %u\n", MAX_BLOCK_SIZE);
	PRINTF("total sectors count            : %u\n", NUMBER_OF_SECTORS);
	PRINTF("sector byte size               : %u\n", MAX_SECTOR_SIZE);
	PRINTF("\n");

	create_root(disk, &sb, &gd);

	return EXT2_SUCCESS;
}

int fill_super_block(EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector, UINT32 log_block_size)
{
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 block_per_group = byte_per_block << 3;
    BYTE sector_per_block = byte_per_block / bytesPerSector;
    UINT32 number_of_group = numberOfSectors / (sector_per_block * block_per_group);


	ZeroMemory(sb, sizeof(EXT2_SUPER_BLOCK));

	// max_inode_count = disk 크기 * block 크기
	sb->max_inode_count = (bytesPerSector * numberOfSectors) / byte_per_block;
	sb->block_count = numberOfSectors / sector_per_block;
	sb->reserved_block_count = (UINT32)( (double)sb->block_count * (5./100.) );
	// super block 초기화 당시 free block, inode 개수 = 최대 block, inode 개수
	sb->free_block_count = sb->block_count;
    sb->free_inode_count = sb->max_inode_count;
	// 첫 번째 블록
    sb->first_data_block = 0x00; 
    sb->log_block_size = log_block_size; // 0, 1, 2

    sb->log_fragmentation_size = 2;	// 0, 1, 2 (2 - 임시)

    sb->block_per_group = block_per_group;

    sb->fragmentation_per_group;

    sb->inode_per_group = sb->max_inode_count / number_of_group;

	// 0
	sb->mtime;
	sb->wtime;

	sb->mount_cnt = 0;
	sb->max_mount_cnt = 0xFFFF;

    sb->magic_signature = 0xEF53;
    sb->state = 1;
    sb->errors = 0;

	// 0
	sb->minor_version;
	sb->last_check;

	sb->check_interval = 0;
	sb->creator_OS = 0; // linux
	sb->major_version = 0; // inode 크기 고정

	// 0
	sb->def_res_uid; 
	sb->def_res_gid;

	sb->first_non_reserved_inoded = 11; 
	sb->inode_size = 128;

	// 0
	sb->block_group_num;

	// 책에 있는 것 그대로
	sb->feature_compat = 0x24; 
	sb->feature_incompat = 0x02 ; 
	sb->feature_read_only_compat = 0x01;

	// 0
	sb->uuid[16];
	sb->volume_name[16];
	sb->last_mounted[64];
	sb->algorithm_usage_bitmap;
	sb->prealloc_block;
	sb->prealloc_dir_block;
	sb->padding_1;
	sb->journal_uuid[16];	
	sb->journal_inode_num;
	sb->journal_dev;
	sb->last_orphan;
	sb->hash_seed[16];
	sb->def_hash_version;

	sb->sector_per_block = sector_per_block; 

	// 0
	sb->padding_3;
	sb->default_mount_opt; 		
	sb->first_meta_bg;

	return EXT2_SUCCESS;
}

int fill_descriptor_block(EXT2_GROUP_DESCRIPTOR * gd, EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	ZeroMemory(gd, sizeof(EXT2_GROUP_DESCRIPTOR));
	UINT32 number_of_group = numberOfSectors / (sb->sector_per_block * sb->block_per_group);
	
	gd->start_block_of_block_bitmap = ; 
    gd->start_block_of_inode_bitmap = ;
    gd->start_block_of_inode_table = ;
    gd->free_blocks_count = sb->block_per_group;
    gd->free_inodes_count = sb->inode_per_group;
    gd->directories_count = 0; // Block Group 내에 생성된 디렉토리 수
    
	// 0
	gd->padding[2];
    gd->reserved[12];

	return EXT2_SUCCESS;
}

int create_root(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK * sb, EXT2_GROUP_DESCRIPTOR *gd)
{
	const BYTE sector_per_block = sb->sector_per_block;
	BYTE block[MAX_SECTOR_SIZE * sector_per_block];

	UINT32 first_data_block =

	ZeroMemory(block, sizeof(block));
	//read_disk_per_block
	
	return EXT2_SUCCESS;
}

void process_meta_data_for_inode_used(EXT2_NODE * retEntry, UINT32 inode_num, int fileType)
{
}

int insert_entry(UINT32 inode_num, EXT2_NODE * retEntry, int fileType)
{
}

UINT32 get_available_data_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
}

void process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
}

UINT32 expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
}

int meta_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->read_sector(fs->disk, real_index, sector);
}
int meta_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->write_sector(fs->disk, real_index, sector);
}

// ------------------------------------------------------

int read_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    const SECTOR BOOT_BLOCK = 2;
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_BLOCK + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) {
        disk->read_sector(fs->disk, real_sector_index + i, &block_buf[i * disk->bytes_per_sector]);
    }
    return 0;
}

int write_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    const SECTOR BOOT_BLOCK = 2;
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_BLOCK + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) {
        disk->write_sector(fs->disk, real_sector_index + i, &block_buf[i * disk->bytes_per_sector]);
    }
    return 0;
}

int get_inode_location(EXT2_FILESYSTEM *fs, UINT32 inode_num, EXT2_ENTRY_LOCATION *loc) {
	if (inode_num < 1) 
		return -1;
	UINT32 inode_per_group = fs->sb.inode_per_group;
	UINT32 table_index = (inode_num - 1) % inode_per_group;
	UINT32 inode_per_block = (1024 << fs->sb.log_block_size) / 128;

	loc->group = inode_num / inode_per_group;
	loc->block = (table_index / inode_per_block) + fs->gd.start_block_of_inode_table - 1;
	loc->offset = table_index % inode_per_block;

	return 0;
}

int get_inode(EXT2_FILESYSTEM* fs, const UINT32 inode_num, INODE *inodeBuffer) {
	if (inode_num < 1)
		return -1;

	const BYTE sector_per_block = fs->sb.sector_per_block;
	BYTE block[MAX_SECTOR_SIZE * sector_per_block];
	EXT2_ENTRY_LOCATION loc;

	get_inode_location(fs, inode_num, &loc);
	read_disk_per_block(fs, loc.group, loc.block, block);

	*inodeBuffer = ((INODE *)block)[loc.offset];

	return 0;
}

int get_block_location(EXT2_FILESYSTEM *fs, UINT32 block_num, EXT2_ENTRY_LOCATION *loc) {
	if (block_num < 1) 
		return -1;
	UINT32 block_per_group = fs->sb.block_per_group;

	loc->group = block_num / block_per_group;
	loc->block = block_num % block_per_group;
	loc->offset = 0;

	return 0;
}

// ------------------------------------------------------


/*
int data_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->read_sector(fs->disk, real_index, sector);
}
int data_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->write_sector(fs->disk, real_index, sector);
}*/

unsigned char toupper(unsigned char ch);
int isalpha(unsigned char ch);
int isdigit(unsigned char ch);

void upper_string(char* str, int length)
{
	while (*str && length-- > 0)
	{
		*str = toupper(*str);
		str++;
	}
}

int format_name(EXT2_FILESYSTEM* fs, char* name)
{
	UINT32	i, length;
	UINT32	extender = 0, nameLength = 0;
	UINT32	extenderCurrent = 8;
	BYTE	regularName[MAX_ENTRY_NAME_LENGTH];

	memset(regularName, 0x20, sizeof(regularName));
	length = strlen(name);

	if (strncmp(name, "..", 2) == 0)
	{
		memcpy(name, "..         ", 11);
		return EXT2_SUCCESS;
	}
	else if (strncmp(name, ".", 1) == 0)
	{
		memcpy(name, ".          ", 11);
		return EXT2_SUCCESS;
	}
	else
	{
		upper_string(name, MAX_ENTRY_NAME_LENGTH);

		for (i = 0; i < length; i++)
		{
			if (name[i] != '.' && !isdigit(name[i]) && !isalpha(name[i]))
				return EXT2_ERROR;

			if (name[i] == '.')
			{
				if (extender)
					return EXT2_ERROR;
				extender = 1;
			}
			else if (isdigit(name[i]) || isalpha(name[i]))
			{
				if (extender)
					regularName[extenderCurrent++] = name[i];
				else
					regularName[nameLength++] = name[i];
			}
			else
				return EXT2_ERROR;
		}

		if (nameLength > 8 || nameLength == 0 || extenderCurrent > 11)
			return EXT2_ERROR;
	}

	memcpy(name, regularName, sizeof(regularName));
	return EXT2_SUCCESS;
}

int lookup_entry(EXT2_FILESYSTEM* fs, const int inode, const char* name, EXT2_NODE* retEntry)
{
}

int find_entry_at_sector(const BYTE* sector, const BYTE* formattedName, UINT32 begin, UINT32 last, UINT32* number)
{
}

int find_entry_on_root(EXT2_FILESYSTEM* fs, INODE inode, char* formattedName, EXT2_NODE* ret)
{
}

int find_entry_on_data(EXT2_FILESYSTEM* fs, INODE first, const BYTE* formattedName, EXT2_NODE* ret)
{
}

int read_root_sector(EXT2_FILESYSTEM* fs, BYTE* sector)
{
	
	return 0;
}

int ext2_create(EXT2_NODE* parent, char* entryName, EXT2_NODE* retEntry)
{
	
    return EXT2_SUCCESS;
}


int get_data_block_at_inode(EXT2_FILESYSTEM *fs, INODE inode, UINT32 number)
{
}

int ext2_read_superblock(EXT2_FILESYSTEM* fs, EXT2_NODE* root)
{
	
	return EXT2_SUCCESS;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs)
{
}

int set_inode_onto_inode_table(EXT2_FILESYSTEM *fs, const UINT32 which_inode_num_to_write, INODE * inode_to_write)
{
}

int ext2_lookup(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	
	return 0;
}

int ext2_read_dir(EXT2_NODE* dir, EXT2_NODE_ADD adder, void* list)
{
	
	return EXT2_SUCCESS;
}

int read_dir_from_sector(EXT2_FILESYSTEM* fs, BYTE* sector, EXT2_NODE_ADD adder, void* list)
{
	
	return 0;
}

char* my_strncpy(char* dest, const char* src, int length)
{
	while (*src && *src != 0x20 && length-- > 0)
		*dest++ = *src++;

	return dest;
}

int ext2_mkdir(const EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	
	return EXT2_SUCCESS;
}