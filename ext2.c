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

int write_block(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK* sb, SECTOR* block, unsigned int start_block)
{
	const int BOOT_SECTOR_BASE = 1024 / MAX_SECTOR_SIZE;
	SECTOR sector_index = start_block * sb->sector_per_block + BOOT_SECTOR_BASE;

    for (int i = 0; i < sb->sector_per_block; i++)
	{
        if (disk->write_sector(disk, sector_index + i, &block[i * disk->bytes_per_sector]) == EXT2_ERROR) {
			PRINTF("write_block() function error\n");
			return EXT2_ERROR;
		}
    }
	return EXT2_SUCCESS;
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
	
	printf("1\n");
	int i, gi, j;

	/* super block 채우기 */
	if (fill_super_block(&sb, disk->number_of_sectors, disk->bytes_per_sector, log_block_size) != EXT2_SUCCESS)
		return EXT2_ERROR;

	printf("2\n");
	
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 number_of_group = disk->number_of_sectors / (sb.sector_per_block * sb.block_per_group);

	const UINT32 sector_per_block = sb.sector_per_block;
	BYTE block[MAX_SECTOR_SIZE * sector_per_block];

	ZeroMemory(block, sizeof(block));
	memcpy(block, &sb, sizeof(sb));
	
	if (write_block(disk, &sb, block, 0) == EXT2_ERROR)
		return EXT2_ERROR; 
	
	printf("3\n");
	
	/* 0번 descriptor 채우기 */
	if (fill_descriptor_block(&gd, &sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;

	printf("4\n");

	/* descriptor table 채우기 */

	// 0번 block group과 달리, 1번~ block groups는 inode 예약 영역이 없고, 
	// root block이 없어서 free count 다시 초기화
	UINT32 descriptor_per_block = (1024 << sb.log_block_size) / 32;
	int descriptor_block_index = 0;

	gd_another_group = gd;
	gd_another_group.free_inodes_count = sb.inode_per_group;
	gd_another_group.free_blocks_count = sb.free_block_count / number_of_group;

	ZeroMemory(block, sizeof(block));

	for (j = 0; j < number_of_group; j++)
	{
		if (j == 0) memcpy(block + j * sizeof(gd), &gd, sizeof(gd));
		else memcpy(block + j * sizeof(gd_another_group), &gd_another_group, sizeof(gd_another_group));

		// 한 block 꽉 차면 다음 block으로 넘어감
		if ((j + 1) % descriptor_per_block == 0) 
		{
			if (write_block(disk, &sb, block, 1 + descriptor_block_index++) == EXT2_ERROR)
				return EXT2_ERROR; 
			ZeroMemory(block, sizeof(block));
		}
	} 

	// 꽉 채우지 못한 마지막 block 써줌
	if (number_of_group % descriptor_per_block != 0)
	{
		if (write_block(disk, &sb, block, 1 + descriptor_block_index) == EXT2_ERROR)
				return EXT2_ERROR;
	}

	printf("5\n");

	/* block bitmap 채우기 */
	ZeroMemory((block), sizeof(block));
	UINT32 number_of_descriptor_block = ( number_of_group * 32 + ( byte_per_block - 1 ) ) / byte_per_block;
	/*
	UINT32 number_of_
	UINT32 number_of_used_block = number_of_descriptor_block + number_of_inode_table_block + 3;
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
	// UINT32 number_of_used_block = number_of_descriptor_block + number_of_inode_table_block + 3;

	block[0] = 0xff; // 8개
	block[1] = 0x03; // 2개  inode 예약 영역 10개 잡아줌

	if (write_block(disk, &sb, block, gd.start_block_of_inode_bitmap) == EXT2_ERROR)
		return EXT2_ERROR;

	printf("6\n");

	/* inode table 채우기 */
	ZeroMemory(block, sizeof(block));

	for (i = gd.start_block_of_inode_table; i < sb.first_meta_bg; i++)
	{
		if (write_block(disk, &sb, block, i) == EXT2_ERROR)
			return EXT2_ERROR;
	}

	/* 1번째 block group부터 차례로 super block ~ inode table 채움 */
	for (gi = 1; gi < number_of_group; gi++)
	{
		sb.block_group_num = gi;
		
		gd.start_block_of_block_bitmap = sb.block_group_num * sb.block_per_group + number_of_descriptor_block + 1;
    	gd.start_block_of_inode_bitmap = gd.start_block_of_block_bitmap + 1;
    	gd.start_block_of_inode_table = gd.start_block_of_inode_bitmap + 1;

		gd_another_group.start_block_of_block_bitmap = sb.block_group_num * sb.block_per_group + number_of_descriptor_block + 1;
    	gd_another_group.start_block_of_inode_bitmap = gd.start_block_of_block_bitmap + 1;
    	gd_another_group.start_block_of_inode_table = gd.start_block_of_inode_bitmap + 1;

		sb.first_meta_bg = gd.start_block_of_inode_table // inode table 시작 block
							+ ((sb.inode_per_group + (sb.inode_per_group - 1)) >> (3 + sb.log_block_size)) // inode table이 차지하는 block 수
							+ 3; // super block + block bitmap + inode bitmap

		/* gi번째 group에 super block 채우기 */
		ZeroMemory(block, sizeof(block));
		memcpy(block, &sb, sizeof(sb));

		if (write_block(disk, &sb, block, sb.block_per_group * gi) == EXT2_ERROR)
			return EXT2_ERROR;
		// free_blocks, free_inodes 0으로 초기화 X???????

		/* gi번째 group에 descriptor table 채우기 */
		ZeroMemory(block, sizeof(block));
		descriptor_block_index = 0;

		for (j = 0; j < number_of_group; j++)
		{
			if (j == 0) memcpy(block + j * sizeof(gd), &gd, sizeof(gd));
			else memcpy(block + j * sizeof(gd_another_group), &gd_another_group, sizeof(gd_another_group));

			// 한 block 꽉 차면 다음 block으로 넘어감
			if ((j + 1) % descriptor_per_block == 0) 
			{
				if (write_block(disk, &sb, block, sb.block_per_group * gi + 1 + descriptor_block_index++) == EXT2_ERROR)
					return EXT2_ERROR;
				ZeroMemory(block, sizeof(block));
			}
		} 
		// 꽉 채우지 못한 마지막 block 써줌
		if (number_of_group % descriptor_per_block != 0) 
		{
			if (write_block(disk, &sb, block, sb.block_per_group * gi + 1 + descriptor_block_index) == EXT2_ERROR)
				return EXT2_ERROR;
		}

		/* gi번째 group에 block bitmap 채우기 */
		ZeroMemory(block, sizeof(block));
		block[0] = 0xff;
		block[1] = 0xff;
		block[2] = 0x01;
		
		if (write_block(disk, &sb, block, gd.start_block_of_block_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;

		/* gi번째 group에 inode bitmap 채우기 */
		ZeroMemory(block, sizeof(block));

		if (write_block(disk, &sb, block, gd.start_block_of_inode_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;
		/* gi번째 group에 inode table 채우기 */
		ZeroMemory(block, sizeof(block));

		for (i = gd.start_block_of_inode_table; i < sb.first_meta_bg; i++)
		{
			if (write_block(disk, &sb, block, i) == EXT2_ERROR)
			return EXT2_ERROR;
		}

	}

	printf("7\n");

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode structure   : %u\n", sb.inode_size);
	PRINTF("block byte size                : %u\n", byte_per_block);
	PRINTF("total sectors count            : %u\n", disk->number_of_sectors);
	PRINTF("sector byte size               : %u\n", MAX_SECTOR_SIZE);
	PRINTF("\n");

	if (create_root(disk, &sb, &gd) != EXT2_SUCCESS)
	{
		PRINTF("create_root() function error\n");
		return EXT2_ERROR;
	}

	printf("8\n");

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
	UINT32 max_inode_count = numberOfSectors / sector_per_block / 2;
	UINT32 inode_per_group = max_inode_count / number_of_group;
	UINT32 number_of_inode_block =(inode_per_group + (inode_per_block - 1)) / inode_per_block; // inode table이 차지하는 block 수
	UINT32 number_of_used_block = number_of_descriptor_block + number_of_inode_block + 3; // 3 : super block + block bitmap + inode bitmap

	ZeroMemory(sb, sizeof(EXT2_SUPER_BLOCK));

	// max_inode_count = disk 크기 * block 크기
	sb->max_inode_count = max_inode_count;
	sb->block_count = numberOfSectors / sector_per_block;
	sb->reserved_block_count = (UINT32)( (double)sb->block_count * (5./100.) );

	// 전체 block group에서 free한 block, inode의 개수
	sb->free_block_count = sb->block_count - number_of_used_block * number_of_group - 1; // 1 : root
    sb->free_inode_count = sb->max_inode_count - 10; // 10 : 예약된 inode

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
    
	gd->free_blocks_count = (sb->free_block_count + 1) / number_of_group ;
    gd->free_inodes_count = sb->inode_per_group - 10;
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

	printf("1\n");

	// set inode
	read_block(disk, sb, block, inode_table_block);
	printf("1-1\n");
	INODE *root_inode = ((INODE *)block) + 1; // 2번 inode
	root_inode->mode = 0x41A4; // directory, 644
	root_inode->link_cnt = 2; // ".", ".."
	root_inode->i_block[0] = root_entry_block;
	write_block(disk, sb, block, inode_table_block);

	printf("2\n");

	// set dir_entry
	// "." entry
	ZeroMemory(block, sizeof(block));
	EXT2_DIR_ENTRY *entry = (EXT2_DIR_ENTRY *)block;
	entry->inode = 2;
	entry->file_type = EXT2_FT_DIR;
	entry->name_len = strlen(".");
	memcpy(entry->name, ".", entry->name_len);
	entry->record_len = sizeof(EXT2_DIR_ENTRY) - EXT2_NAME_LEN + entry->name_len;

	printf("3\n");

	// ".." entry
	EXT2_DIR_ENTRY *prev_entry = entry;
	entry = (EXT2_DIR_ENTRY *)(block + prev_entry->record_len);
	entry->inode = 2;
	entry->file_type = EXT2_FT_DIR;
	entry->name_len = strlen("..");
	memcpy(entry->name, "..", entry->name_len);
	entry->record_len = (1024 << sb->log_block_size) - prev_entry->record_len;

	write_block(disk, sb, block, root_entry_block);

	printf("4\n");

	// set block_bitmap
	read_block(disk, sb, block, block_bitmap_block);
	(((volatile unsigned int *) block)[root_entry_block >> 5]) |= (1UL << (root_entry_block & 31));
	write_block(disk, sb, block, block_bitmap_block);

	printf("5\n");

	return EXT2_SUCCESS;
}

void process_meta_data_for_inode_used(EXT2_NODE * retEntry, UINT32 inode_num, int fileType)
{
	return EXT2_ERROR;
}

int insert_entry(UINT32 inode_num, EXT2_NODE * retEntry, int fileType)
{
	return EXT2_ERROR;
}

UINT32 get_available_data_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	return EXT2_ERROR;
}

void process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
}

UINT32 expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	return EXT2_ERROR;
}

int meta_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_SECTOR_BASE = 1024 / MAX_SECTOR_SIZE;
	SECTOR real_index = BOOT_SECTOR_BASE + group * fs->sb.block_per_group + block;

	return fs->disk->read_sector(fs->disk, real_index, sector);
}
int meta_write(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
	const SECTOR BOOT_BLOCK = 1;
	SECTOR real_index = BOOT_BLOCK + group * fs->sb.block_per_group + block;

	return fs->disk->write_sector(fs->disk, real_index, sector);
}

// ------------------------------------------------------

// addr : 해당 group의 block_bitmap 시작 주소
// num : 해당 group에서의 block number
static int test_block_bit( int nr, const volatile void* addr )
{
	 return ((1UL << (nr & 31)) & (((const volatile unsigned int *) addr)[nr >> 5])) != 0;
}

void change_block_bit(EXT2_FILESYSTEM *fs, UINT32 num) 
{
	UINT32 boot_block = 1024 / MAX_SECTOR_SIZE;
	UINT32 bitmap = ( (num / fs->sb.block_per_group) * fs->sb.block_per_group + fs->gd.start_block_of_block_bitmap ) 
					* fs->sb.sector_per_block + boot_block;
	//disk->pdata[fs->disk->bytes_per_sector * bitmap]
	UINT32 nr = num % fs->sb.block_per_group;
	volatile void *addr = ((BYTE *)fs->disk->pdata) + fs->disk->bytes_per_sector * bitmap;

	if (test_block_bit(nr, addr) == 1) 
	{
		(((volatile unsigned int *)addr)[nr>>5]) &= (0xFFFFFFFF ^ (1UL << (nr & 31)));
	}
	else 
	{
		(((volatile unsigned int *) addr)[nr >> 5]) |= (1UL << (nr & 31));
	}
}

int read_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    const SECTOR BOOT_SECTOR_BASE = 1024 / MAX_SECTOR_SIZE;
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_SECTOR_BASE + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) 
	{
        if ( disk->read_sector(fs->disk, real_sector_index + i, &block_buf[i * disk->bytes_per_sector]) == EXT2_ERROR)
			return EXT2_ERROR;
    }
    return EXT2_SUCCESS;
}

int write_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    const SECTOR BOOT_SECTOR_BASE = 1024 / MAX_SECTOR_SIZE;
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_SECTOR_BASE + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) 
	{
        if ( disk->write_sector(fs->disk, real_sector_index + i, &block_buf[i * disk->bytes_per_sector]) == EXT2_ERROR)
			return EXT2_ERROR;
    }
    return EXT2_SUCCESS;
}

int get_inode_location(EXT2_FILESYSTEM *fs, UINT32 inode_num, EXT2_ENTRY_LOCATION *loc) {
	if (inode_num < 1) 
		return EXT2_ERROR;

	UINT32 inode_per_group = fs->sb.inode_per_group;
	UINT32 table_index = (inode_num - 1) % inode_per_group;
	UINT32 inode_per_block = (1024 << fs->sb.log_block_size) / 128;
	// 128말고 fs->sb.inode_size 하면 안될까
	
	loc->group = inode_num / inode_per_group;
	loc->block = (table_index / inode_per_block) + fs->gd.start_block_of_inode_table - 1;
	loc->offset = table_index % inode_per_block;

	return EXT2_SUCCESS;
}

int get_inode(EXT2_FILESYSTEM* fs, const UINT32 inode_num, INODE *inodeBuffer) {
	if (inode_num < 1)
		return EXT2_ERROR;

	const BYTE sector_per_block = fs->sb.sector_per_block;
	BYTE block[MAX_SECTOR_SIZE * sector_per_block];
	EXT2_ENTRY_LOCATION loc;

	if (get_inode_location(fs, inode_num, &loc) == EXT2_ERROR)
		return EXT2_ERROR; 

	if (read_disk_per_block(fs, loc.group, loc.block, block) == EXT2_ERROR)
		return EXT2_ERROR;

	*inodeBuffer = ((INODE *)block)[loc.offset];

	return EXT2_SUCCESS;
}

int get_block_location(EXT2_FILESYSTEM *fs, UINT32 block_num, EXT2_ENTRY_LOCATION *loc) {
	if (block_num < 1) 
		return EXT2_ERROR;
	UINT32 block_per_group = fs->sb.block_per_group;

	loc->group = block_num / block_per_group;
	loc->block = block_num % block_per_group;
	loc->offset = 0;

	return EXT2_SUCCESS;
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
	BYTE	regularName[EXT2_NAME_LEN];

	memset(regularName, 0, sizeof(regularName));
	length = strlen(name);

	if (strcmp(name, "..") == 0 | strcmp(name, ".") == 0)
	{
		return EXT2_SUCCESS;
	}
	else
	{
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

		if (nameLength > EXT2_NAME_LEN || nameLength == 0 || extenderCurrent > 11)
			return EXT2_ERROR;
	}

	memcpy(name, regularName, sizeof(regularName));
	return EXT2_SUCCESS;
}

int lookup_entry(EXT2_FILESYSTEM* fs, const int inode, const char* name, EXT2_NODE* retEntry)
{
	return EXT2_ERROR;
}

int find_entry_at_sector(const BYTE* sector, const BYTE* formattedName, UINT32 begin, UINT32 last, UINT32* number)
{
	return EXT2_ERROR;
}

int find_entry_on_root(EXT2_FILESYSTEM* fs, INODE inode, char* formattedName, EXT2_NODE* ret)
{
	return EXT2_ERROR;
}

int find_entry_on_data(EXT2_FILESYSTEM* fs, INODE first, const BYTE* formattedName, EXT2_NODE* ret)
{
	return EXT2_ERROR;
}

int read_root_sector(EXT2_FILESYSTEM* fs, EXT2_DIR_ENTRY *root)
{
	root->file_type = EXT2_FT_DIR;
	root->inode = 2;
	root->name_len = strlen(VOLUME_LABLE);
	memcpy(root->name, VOLUME_LABLE, root->name_len);
	root->record_len = sizeof(EXT2_DIR_ENTRY) - EXT2_NAME_LEN + root->name_len;

	return EXT2_SUCCESS;
}

int ext2_create(EXT2_NODE* parent, char* entryName, EXT2_NODE* retEntry)
{
	
    return EXT2_SUCCESS;
}


int get_data_block_at_inode(EXT2_FILESYSTEM *fs, INODE inode, UINT32 number)
{
	return EXT2_ERROR;
}

int ext2_read_superblock(EXT2_FILESYSTEM* fs, EXT2_NODE* root)
{
	INT result;
	const UINT32 sector_per_block = fs->sb.sector_per_block;
	BYTE block[MAX_SECTOR_SIZE * sector_per_block];
	UINT32 super_block = 0; // super block 시작 block
	UINT32 group_descriptor_block = 1; // group descriptor table 시작 block

	if (fs == NULL || fs->disk == NULL)
	{
		WARNING("DISK OPERATIONS : %p\nEXT2_FILESYSTEM : %p\n", fs, fs->disk);
		return EXT2_ERROR;
	}

	/* fs에 0번 block group의 super block, group descriptor table 복사 */
	read_disk_per_block(fs, 0, super_block, block);
	memcpy(&fs->sb, block, sizeof(EXT2_SUPER_BLOCK));
	read_disk_per_block(fs, 0, group_descriptor_block, block);
	memcpy(&fs->gd, block, sizeof(EXT2_GROUP_DESCRIPTOR));

	/* super block인지 확인 */
	if (fs->sb.magic_signature != 0xEF53) 
		return EXT2_ERROR;

	/* root 디렉토리로 엔트리 채우기 */
	ZeroMemory(root, sizeof(EXT2_NODE));
	if (read_root_sector(fs, &root->entry) == EXT2_ERROR)
	root->fs = fs;

	return EXT2_SUCCESS;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs)
{
	return EXT2_ERROR;
}

int set_inode_onto_inode_table(EXT2_FILESYSTEM *fs, const UINT32 which_inode_num_to_write, INODE * inode_to_write)
{
	return EXT2_ERROR;
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