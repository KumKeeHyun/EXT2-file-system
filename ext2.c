#include <bitset>

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

void write_block(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK* sb, SECTOR* block, unsigned int start_block)
{
	const int BOOT_SECTOR_BASE = 2;
	SECTOR sector_index = start_block * sb->sector_per_block + BOOT_SECTOR_BASE;

    for (int i = 0; i < sb->sector_per_block; i++) 
	{
        disk->write_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]);
    }
}

void read_block(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK* sb, SECTOR* block, unsigned int start_block) 
{
	const int BOOT_SECTOR_BASE = 2;
	SECTOR sector_index = start_block * sb->sector_per_block + BOOT_SECTOR_BASE;

	for (int i = 0; i < sb->sector_per_block; i++)
	{
		disk->read_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]);
	}
}

int ext2_format(DISK_OPERATIONS* disk, UINT32 log_block_size)
{
	EXT2_SUPER_BLOCK sb;
	EXT2_GROUP_DESCRIPTOR gd;
	EXT2_GROUP_DESCRIPTOR  gd_another_group;
	
	int i, gi, j;

	/* super block 채우기 */
	if (fill_super_block(&sb, disk->number_of_sectors, disk->bytes_per_sector, log_block_size) != EXT2_SUCCESS)
		return EXT2_ERROR;
	
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 number_of_group = disk->number_of_sectors / (sb.sector_per_block * sb.block_per_group);

	const UINT32 sector_per_block = sb.sector_per_block;
	char block[MAX_SECTOR_SIZE * sector_per_block];

	ZeroMemory(block, sizeof(block));
	memcpy(block, &sb, sizeof(sb));

	write_block(disk, &sb, block, 0);

	/* descriptor 채우기 */
	if (fill_descriptor_block(&gd, &sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;

	gd_another_group = gd;

	/* descriptor table 채우기 */
	ZeroMemory(block, sizeof(block));

	for (j = 0; j < number_of_group; j++)
	{
		if (j == 0) memcpy(block + j * sizeof(gd), &gd, sizeof(gd));
		else memcpy(block + j * sizeof(gd_another_group), &gd_another_group, sizeof(gd_another_group));
	} 

	// write_block 없음???

	/* block bitmap 채우기
	ZeroMemory((block), sizeof(block));
	UINT32 number_of_descriptor_block = ( number_of_group * 32 + ( byte_per_block - 1 ) ) / byte_per_block;
	
	// set n + 3개 bit & root inode bit
	for (int i = 0; i < number_of_descriptor_block + 3; i++)
	{
		// block[i] 내의 j번째 비트 set
		for (int j = 0; j < 8; j++)
		{
			block[i] = block[i] | (1 << j);
		}
		
	}

	// number_of_descriptor + 3 까지 1, root bit 1로 set
	bitset<number_of_descriptor_block + 5> bit;
	bit.set(); // number_of_descriptor + 5개 비트 1로 set
	bit.set(number_of_descriptor_block - 1, 0); // number_of_descriptor_block + 4 번째 비트 0으로 reset
	
	bit.to_char();
	
	write_block(disk, &sb, block, gd.start_block_of_block_bitmap);
	*/

	/* inode bitmap 채우기 */
	ZeroMemory(block, sizeof(block));

	block[0] = 0xff; // 8개
	block[1] = 0x03; // 2개  inode 예약 영역 10개 잡아줌

	write_block(disk, &sb, block, gd.start_block_of_inode_bitmap);

	/* inode table 채우기 */
	ZeroMemory(block, sizeof(block));

	for (i = gd.start_block_of_inode_table; i < sb.first_meta_bg; i++)
		write_block(disk, &sb, block, i);

	/* 1번째 block group부터 차례로 super block ~ inode table 채움 */
	for (gi = 1; gi < number_of_group; gi++)
	{
		sb.block_group_num = gi;
		
		gd.start_block_of_block_bitmap = sb.block_group_num * sb.block_per_group + number_of_descriptor_block + 1;
    	gd.start_block_of_inode_bitmap = gd.start_block_of_block_bitmap + 1;
    	gd.start_block_of_inode_table = gd.start_block_of_inode_bitmap + 1;

		sb.first_meta_bg = gd.start_block_of_inode_table // inode table 시작 block
							+ ((sb.inode_per_group + (sb.inode_per_group - 1)) >> (3 + sb.log_block_size)) // inode table이 차지하는 block 수
							+ 3; // super block + block bitmap + inode bitmap

		/* gi번째 group에 super block 채우기 */
		ZeroMemory(block, sizeof(block));
		memcpy(block, &sb, sizeof(sb));

		write_block(disk, &sb, block, sb.block_per_group * gi);

		// free_blocks, free_inodes 0으로 초기화 X???????

		/* gi번째 group에 descriptor table 채우기 */
		ZeroMemory(block, sizeof(block));
		for (j = 0; j < number_of_group; j++)
		{
			memcpy(block + j * sizeof(gd), &gd, sizeof(gd));
		}
		write_block(disk, &sb, block, sb.block_per_group * gi + 1);

		/* gi번째 group에 block bitmap 채우기 */
		ZeroMemory(block, sizeof(block));
		block[0] = 0xff;
		block[1] = 0xff;
		block[2] = 0x01;
		
		write_block(disk, &sb, block, gd.start_block_of_block_bitmap);

		/* gi번째 group에 inode bitmap 채우기 */
		ZeroMemory(block, sizeof(block));

		write_block(disk, &sb, block, gd.start_block_of_inode_bitmap);

		/* gi번째 group에 inode table 채우기 */
		ZeroMemory(block, sizeof(block));

		for (i = gd.start_block_of_inode_table; i < sb.first_meta_bg; i++)
			write_block(disk, &sb, block, i);
	}
    

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode structure   : %u\n", sb.inode_size);
	PRINTF("block byte size                : %u\n", byte_per_block);
	PRINTF("total sectors count            : %u\n", disk->number_of_sectors);
	PRINTF("sector byte size               : %u\n", MAX_SECTOR_SIZE);
	PRINTF("\n");

	create_root(disk, &sb, &gd_another_group);

	return EXT2_SUCCESS;
}

int fill_super_block(EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector, UINT32 log_block_size)
{
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 block_per_group = byte_per_block << 3;
    BYTE sector_per_block = byte_per_block / bytesPerSector;
    UINT32 number_of_group = numberOfSectors / (sector_per_block * block_per_group);

	UINT32 number_of_descriptor_block = ( number_of_group * 32 + ( byte_per_block - 1 ) ) / byte_per_block; 
	UINT32 inode_per_block = 1 << (3 + log_block_size);
	UINT32 max_inode_count = (bytesPerSector * numberOfSectors) / byte_per_block;
	UINT32 inode_per_group = max_inode_count / number_of_group;
	UINT32 number_of_inode_block =(inode_per_group + (inode_per_block - 1)) / inode_per_block; // inode table이 차지하는 block 수
	UINT32 number_of_used_block = number_of_descriptor_block + number_of_inode_block + 3; // 3 : super block + block bitmap + inode bitmap

	ZeroMemory(sb, sizeof(EXT2_SUPER_BLOCK));

	// max_inode_count = disk 크기 * block 크기
	sb->max_inode_count = max_inode_count;
	sb->block_count = numberOfSectors / sector_per_block;
	sb->reserved_block_count = (UINT32)( (double)sb->block_count * (5./100.) );

	// 전체 block group에서 free한 block, inode의 개수
	sb->free_block_count = sb->block_count - number_of_used_block * number_of_group;
    sb->free_inode_count = sb->max_inode_count;

	// 첫 번째 블록
    sb->first_data_block = 0x00; 
    sb->log_block_size = log_block_size; // 0, 1, 2

    sb->log_fragmentation_size = 2;	// 0, 1, 2 (2 - 임시)

    sb->block_per_group = block_per_group;

    sb->fragmentation_per_group;

    sb->inode_per_group = inode_per_group;

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

	sb->first_ino = 11; 
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

	sb->first_meta_bg = sb->block_group_num * sb->block_per_group // 해당 블록 그룹의 첫번째 블록
						+ number_of_used_block; // 그룹내에서 meta block 이전까지의 블록의 개수

	return EXT2_SUCCESS;
}

int fill_descriptor_block(EXT2_GROUP_DESCRIPTOR * gd, EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	UINT32 byte_per_block = 1024 << sb->log_block_size;
	UINT32 number_of_group = numberOfSectors / (sb->sector_per_block * sb->block_per_group);
	UINT32 number_of_descriptor_block = ( number_of_group * 32) / byte_per_block;

	ZeroMemory(gd, sizeof(EXT2_GROUP_DESCRIPTOR));

	gd->start_block_of_block_bitmap = sb->block_group_num * sb->block_per_group + number_of_descriptor_block + 1;
    gd->start_block_of_inode_bitmap = gd->start_block_of_block_bitmap + 1;
    gd->start_block_of_inode_table = gd->start_block_of_inode_bitmap + 1;
    
	gd->free_blocks_count = sb->free_block_count / number_of_group;
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

	UINT32 block_bitmap_block = gd->start_block_of_block_bitmap;
	UINT32 inode_table_block = gd->start_block_of_inode_table;
	UINT32 root_entry_block = sb->first_meta_bg;

	read_block(disk, sb, block, inode_table_block);
	INODE *root_inode = ((INODE *)block) + 1; // 2번 inode
	root_inode->mode = 0x41A4; // directory, 644
	root_inode->link_cnt = 2; // ".", ".." ??
	root_inode->i_block[0] = root_entry_block;
	write_block(disk, sb, block, inode_table_block);

	ZeroMemory(block, sizeof(block));
	EXT2_DIR_ENTRY entry;
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