typedef struct
{
	char*	address;
} DISK_MEMORY;

#include "ext2.h"
#include "ext2_shell.h"
#define MIN( a, b )					( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )					( ( a ) > ( b ) ? ( a ) : ( b ) )

#define GET_RECORD_LEN(entry) 		((entry)->name_len + 8)

int ext2_write(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	return 0;
}

UINT32 get_free_inode_number(EXT2_FILESYSTEM* fs);

int write_block(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK* sb, BYTE* block, unsigned int start_block)
{
	SECTOR sector_index = start_block * sb->sector_per_block + BOOT_SECTOR_BASE;

    for (int i = 0; i < sb->sector_per_block; i++)
	{
        if (disk->write_sector(disk, sector_index + i, &(block[i * disk->bytes_per_sector])) == EXT2_ERROR) {
			PRINTF("write_block() function error\n");
			return EXT2_ERROR;
		}
    }
	return EXT2_SUCCESS;
}

int read_block(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK* sb, BYTE* block, unsigned int start_block) 
{
	SECTOR sector_index = start_block * sb->sector_per_block + BOOT_SECTOR_BASE;

	for (int i = 0; i < sb->sector_per_block; i++)
	{
		if(disk->read_sector(disk, sector_index + i, &(block[i * disk->bytes_per_sector]))== EXT2_ERROR) {
			PRINTF("read_block() function error\n");
			return EXT2_ERROR;
		}
	}
	return EXT2_SUCCESS;
}

int ext2_format(DISK_OPERATIONS* disk, UINT32 log_block_size)
{
	EXT2_SUPER_BLOCK sb;
	EXT2_GROUP_DESCRIPTOR gd;
	EXT2_GROUP_DESCRIPTOR  gd_another_group;
	
	int i, gi, j;

	/* super block 채우기 */
	if (fill_super_block(&sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;
	
	UINT32 byte_per_block = 1024 << log_block_size;
    UINT32 number_of_group = disk->number_of_sectors / (sb.sector_per_block * sb.block_per_group);

	//BYTE block[MAX_SECTOR_SIZE * sector_per_block];
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];

	BYTE *block_ptr = block;
	printf ("%p\n",block_ptr);
	ZeroMemory(block, sizeof(block));
	memcpy(block, &sb, sizeof(sb));

	if (write_block(disk, &sb, block, 0) == EXT2_ERROR)
		return EXT2_ERROR; 
	
	/* 0번 descriptor 채우기 */
	if (fill_descriptor_block(&gd, &sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;

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

	/* block bitmap 채우기 */
	ZeroMemory((block), sizeof(block));

	for (unsigned int i = 0; i < sb.first_meta_bg + 1; i++) {
		(((volatile unsigned int *) block)[i >> 5]) |= (1UL << (i & 31));
	}
	if (write_block(disk, &sb, block, gd.start_block_of_block_bitmap) == EXT2_ERROR)
		return EXT2_ERROR;

	/* inode bitmap 채우기 */
	ZeroMemory(block, sizeof(block));

	block[0] = 0xff; // 8개
	block[1] = 0x03; // 2개  inode 예약 영역 10개 잡아줌

	if (write_block(disk, &sb, block, gd.start_block_of_inode_bitmap) == EXT2_ERROR)
		return EXT2_ERROR;

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

		/* gi번째 group에 super block 채우기 */
		ZeroMemory(block, sizeof(block));
		memcpy(block, &sb, sizeof(sb));

		if (write_block(disk, &sb, block, sb.block_per_group * gi) == EXT2_ERROR)
			return EXT2_ERROR;

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
		
		for (unsigned int i = 0; i < sb.first_meta_bg; i++) {
			(((volatile unsigned int *) block)[i >> 5]) |= (1UL << (i & 31));
		}
		
		if (write_block(disk, &sb, block, sb.block_per_group * gi + gd.start_block_of_block_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;

		/* gi번째 group에 inode bitmap 채우기 */
		ZeroMemory(block, sizeof(block));

		if (write_block(disk, &sb, block, sb.block_per_group * gi + gd.start_block_of_inode_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;

		/* gi번째 group에 inode table 채우기 */
		ZeroMemory(block, sizeof(block));

		for (i = sb.block_per_group * gi + gd.start_block_of_inode_table; i < sb.block_per_group * gi + sb.first_meta_bg; i++)
		{
			if (write_block(disk, &sb, block, i) == EXT2_ERROR)
			return EXT2_ERROR;
		}

	}

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode structure   : %u\n", sb.inode_size);
	PRINTF("block byte size                : %u\n", byte_per_block);
	PRINTF("total sectors count            : %u\n", disk->number_of_sectors);
	PRINTF("sector byte size               : %u\n", MAX_SECTOR_SIZE);
	PRINTF("sector per block               : %u\n", sb.sector_per_block);
	PRINTF("number of group                : %u\n", number_of_group);
	PRINTF("inode per group                : %u\n", sb.inode_per_group);
	PRINTF("block per group                : %u\n", sb.block_per_group);
	PRINTF("\n");

	if (create_root(disk, &sb, &gd) != EXT2_SUCCESS)
	{
		PRINTF("create_root() function error\n");
		return EXT2_ERROR;
	}

	return EXT2_SUCCESS;
}

int fill_super_block(EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	UINT32 byte_per_block = 1024 << LOG_BLOCK_SIZE;
    UINT32 block_per_group = byte_per_block << 3;
    BYTE sector_per_block = byte_per_block / bytesPerSector;
    UINT32 number_of_group = (numberOfSectors + (sector_per_block * block_per_group - 1)) / (sector_per_block * block_per_group);
	UINT32 number_of_descriptor_block = ( number_of_group * 32 + ( byte_per_block - 1 ) ) / byte_per_block; 
	UINT32 inode_per_block = 1 << (3 + LOG_BLOCK_SIZE);
	UINT32 max_inode_count = numberOfSectors / sector_per_block / 2;
	UINT32 inode_per_group = max_inode_count / number_of_group;
	UINT32 number_of_inode_block = (inode_per_group + (inode_per_block - 1)) / inode_per_block; // 한 그룹에서 inode table이 차지하는 block 수
	UINT32 number_of_used_block = number_of_descriptor_block + number_of_inode_block + 3; // 3 : super block + block bitmap + inode bitmap
	ZeroMemory(sb, sizeof(EXT2_SUPER_BLOCK));

	// max_inode_count = block 개수 / 2로 약속
	sb->max_inode_count = max_inode_count;
	sb->block_count = numberOfSectors / sector_per_block;
	sb->reserved_block_count = (UINT32)( (double)sb->block_count * (5./100.) );

	// 전체 block group에서 free한 block, inode의 개수
	sb->free_block_count = sb->block_count - number_of_used_block * number_of_group - 1; // 1 : root
    sb->free_inode_count = sb->max_inode_count - 10; // 10 : 예약된 inode

	// 첫 번째 블록
    sb->first_data_block = 0x00; 
    sb->log_block_size = LOG_BLOCK_SIZE; // 0, 1, 2

    sb->log_fragmentation_size = 2;	// 0, 1, 2 (2 - 임시)

    sb->block_per_group = block_per_group;

    // sb->fragmentation_per_group;

    sb->inode_per_group = inode_per_group;

	// 0
	// sb->mtime;
	// sb->wtime;

	sb->mount_cnt = 0;
	sb->max_mount_cnt = 0xFFFF;

    sb->magic_signature = 0xEF53;
    sb->state = 1;
    sb->errors = 0;

	// 0
	// sb->minor_version;
	// sb->last_check;

	sb->check_interval = 0;
	sb->creator_OS = 0; // linux
	sb->major_version = 0; // inode 크기 고정

	// 0
	// sb->def_res_uid; 
	// sb->def_res_gid;

	sb->first_ino = 11; 
	sb->inode_size = 128;
	sb->block_group_num = 0;

	// 책에 있는 것 그대로
	sb->feature_compat = 0x24; 
	sb->feature_incompat = 0x02 ; 
	sb->feature_read_only_compat = 0x01;

	// 0
	// sb->uuid[16];
	// sb->volume_name[16];
	// sb->last_mounted[64];
	// sb->algorithm_usage_bitmap;
	// sb->prealloc_block;
	// sb->prealloc_dir_block;
	// sb->padding_1;
	// sb->journal_uuid[16];	
	// sb->journal_inode_num;
	// sb->journal_dev;
	// sb->last_orphan;
	// sb->hash_seed[16];
	// sb->def_hash_version;

	sb->sector_per_block = sector_per_block; 

	// 0
	// sb->padding_3;
	// sb->default_mount_opt;

	sb->first_meta_bg = number_of_used_block; // 그룹내에서 meta block 이전까지의 블록의 개수

	return EXT2_SUCCESS;
}

int fill_descriptor_block(EXT2_GROUP_DESCRIPTOR * gd, EXT2_SUPER_BLOCK * sb, SECTOR numberOfSectors, UINT32 bytesPerSector)
{
	UINT32 byte_per_block = 1024 << sb->log_block_size;
	UINT32 number_of_group = numberOfSectors / (sb->sector_per_block * sb->block_per_group);
	UINT32 number_of_descriptor_block = ( number_of_group * 32 + (byte_per_block - 1)) / byte_per_block;

	ZeroMemory(gd, sizeof(EXT2_GROUP_DESCRIPTOR));

	gd->start_block_of_block_bitmap = number_of_descriptor_block + 1;
    gd->start_block_of_inode_bitmap = gd->start_block_of_block_bitmap + 1;
    gd->start_block_of_inode_table = gd->start_block_of_inode_bitmap + 1;
    
	gd->free_blocks_count = (sb->free_block_count + 1) / number_of_group ;
    gd->free_inodes_count = sb->inode_per_group - 10;
    gd->directories_count = 0; // Block Group 내에 생성된 디렉토리 수
    
	// 0
	// gd->padding[2];
    // gd->reserved[12];

	return EXT2_SUCCESS;
}

int create_root(DISK_OPERATIONS* disk, EXT2_SUPER_BLOCK * sb, EXT2_GROUP_DESCRIPTOR *gd)
{
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];

	UINT32 block_bitmap_block = gd->start_block_of_block_bitmap;
	UINT32 inode_table_block = gd->start_block_of_inode_table;
	UINT32 root_entry_block = sb->first_meta_bg;

	printf("block_bitmap    : %u\n", block_bitmap_block);
	printf("inode_table     : %u\n", inode_table_block);
	printf("root_entry      : %u\n", root_entry_block);

	// set inode
	ZeroMemory(block, sizeof(block));
	INODE *root_inode = (INODE *)block; // 2번 inode
	root_inode++;
	root_inode->mode = 0x41A4; // directory, 644
	root_inode->link_cnt = 2; // ".", ".."
	root_inode->i_block[0] = root_entry_block;
	write_block(disk, sb, block, inode_table_block);
	//dump_block(disk, sb, inode_table_block);

	// set dir_entry
	// "." entry
	ZeroMemory(block, sizeof(block));
	EXT2_DIR_ENTRY *entry = (EXT2_DIR_ENTRY *)block;
	entry->inode = 2;
	entry->file_type = EXT2_FT_DIR;
	entry->name_len = strlen(".");
	memcpy(entry->name, ".", entry->name_len);
	entry->record_len = GET_RECORD_LEN(entry);

	// ".." entry
	EXT2_DIR_ENTRY *prev_entry = entry;
	entry = (EXT2_DIR_ENTRY *)(block + prev_entry->record_len);
	entry->inode = 2;
	entry->file_type = EXT2_FT_DIR;
	entry->name_len = strlen("..");
	memcpy(entry->name, "..", entry->name_len);
	entry->record_len = (1024 << sb->log_block_size) - prev_entry->record_len;

	write_block(disk, sb, block, root_entry_block);

	return EXT2_SUCCESS;
}

void process_meta_data_for_inode_used(EXT2_NODE * retEntry, UINT32 inode_num, int fileType)
{

}

int insert_entry(UINT32 inode_num, EXT2_NODE * retEntry)
{
	EXT2_NODE new_entry;

	new_entry.fs = retEntry->fs;
	new_entry.entry.name_len = retEntry->entry.name_len;

	// 새로운 entry가 들어가는 위치의 바로 앞에 있는 entry 위치정보를 new_entry->loc에 저장
	if (lookup_entry(retEntry->fs, inode_num, NULL, &new_entry) == EXT2_SUCCESS) 
	{
		retEntry->location = new_entry.location;
		set_entry(retEntry->fs, &new_entry.location, &retEntry->entry);
	}
	else // lookup_entry에서 빈자리 못찾았으면 오류
	{
		return EXT2_ERROR;
	}

	return EXT2_SUCCESS;
}

int set_entry(EXT2_FILESYSTEM * fs, EXT2_ENTRY_LOCATION *loc, EXT2_DIR_ENTRY *new_entry)
{
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	BYTE *block_offset;
	EXT2_DIR_ENTRY *entry;
	UINT32 new_record_len;
	
	read_disk_per_block(fs, loc->group, loc->block, block);

	block_offset = block + loc->offset;

	// entry의 record_len 수정
	entry = (EXT2_DIR_ENTRY *)block_offset;

	if (loc->offset == 0 && GET_RECORD_LEN(entry) == 8) 
	{
		new_entry->record_len = entry->record_len;
		memcpy(entry, new_entry, GET_RECORD_LEN(new_entry));
	}
	else 
	{
		new_record_len = entry->record_len - GET_RECORD_LEN(entry);
		entry->record_len = GET_RECORD_LEN(entry);

		// new entry의 record_len 수정한 뒤에 블럭에 추가
		block_offset += entry->record_len;
		entry = (EXT2_DIR_ENTRY *)block_offset;
		new_entry->record_len = new_record_len;
		memcpy(entry, new_entry, GET_RECORD_LEN(new_entry));
	}
	

	write_disk_per_block(fs, loc->group, loc->block, block);
	return EXT2_SUCCESS;
}

UINT32 get_available_data_block(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
	return EXT2_ERROR;
}

void process_meta_data_for_block_used(EXT2_FILESYSTEM * fs, UINT32 inode_num)
{
}

UINT32 expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num, UINT32 is_dir)
{
	INODE *inode_buf;
	EXT2_ENTRY_LOCATION loc;
	UINT32 i_blk_idx, new_block;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];

	get_inode_location(fs, inode_num, &loc);
	read_disk_per_block(fs, loc.group, loc.block, block);
	inode_buf = ((INODE *)block) + loc.offset;

	// 간접 i_block 추가구현 해야함 일단 고려 안하고 짬
	for (i_blk_idx = 0; i_blk_idx < 15; i_blk_idx++) {
		if (inode_buf->i_block[i_blk_idx] == 0)
			break;
	}
	if (i_blk_idx == 14) {
		printf("i_blocks full\n");
		return EXT2_ERROR;
	}

	new_block = alloc_free_data_block_in_group(fs, 0);
	if (new_block == -1) {
		printf("alloc block error\n");
		return EXT2_ERROR;
	}

	inode_buf->i_block[i_blk_idx] = new_block;
	write_disk_per_block(fs, loc.group, loc.block, block);

	ZeroMemory(block, sizeof(block));

	if (is_dir == EXT2_FT_DIR) 
	{
		((EXT2_DIR_ENTRY *)block)->record_len = (MAX_SECTOR_SIZE * SECTOR_PER_BLOCK);
	}

	get_block_location(fs, new_block, &loc);
	write_disk_per_block(fs, loc.group, loc.block, block);

	return EXT2_SUCCESS;
}

int meta_read(EXT2_FILESYSTEM * fs, SECTOR group, SECTOR block, BYTE* sector)
{
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

int read_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_SECTOR_BASE + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) 
	{
        if ( disk->read_sector(fs->disk, real_sector_index + i, &(block_buf[i * disk->bytes_per_sector])) == EXT2_ERROR)
			return EXT2_ERROR;
    }
    return EXT2_SUCCESS;
}

int write_disk_per_block(EXT2_FILESYSTEM *fs, SECTOR group, SECTOR block, BYTE *block_buf) 
{
    DISK_OPERATIONS* disk = fs->disk;
	SECTOR sector_per_block = fs->sb.sector_per_block;
    SECTOR real_block_index = group * fs->sb.block_per_group + block;
    SECTOR real_sector_index = BOOT_SECTOR_BASE + real_block_index * sector_per_block;

    for (SECTOR i = 0; i < sector_per_block; i++) 
	{
        if ( disk->write_sector(fs->disk, real_sector_index + i, &(block_buf[i * disk->bytes_per_sector])) == EXT2_ERROR)
			return EXT2_ERROR;
    }
    return EXT2_SUCCESS;
}

// inode table에서의 inode 위치
int get_inode_location(EXT2_FILESYSTEM *fs, UINT32 inode_num, EXT2_ENTRY_LOCATION *loc) {
	if (inode_num < 1) 
		return EXT2_ERROR;

	UINT32 inode_per_group = fs->sb.inode_per_group;
	UINT32 table_index = (inode_num - 1) % inode_per_group;
	UINT32 inode_per_block = (1024 << fs->sb.log_block_size) / fs->sb.inode_size;
	// 128말고 fs->sb.inode_size 하면 안될까
	
	loc->group = (inode_num - 1) / inode_per_group;
	loc->block = (table_index / inode_per_block) + fs->gd.start_block_of_inode_table;
	loc->offset = table_index % inode_per_block;

	return EXT2_SUCCESS;
}

int get_inode(EXT2_FILESYSTEM* fs, const UINT32 inode_num, INODE *inodeBuffer) {
	if (inode_num < 1)
		return EXT2_ERROR;

	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
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

// int isalpha(unsigned char ch) {
// 	return ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'));
// }

// int isdigit(unsigned char ch) {
// 	return (ch >= '0' && ch <= '9');
// }

// name의 format을 검사하는 함수로 바꿈
int format_name(EXT2_FILESYSTEM* fs, const char* name)
{
	UINT32	i, length;
	UINT32	extender = 0;
	UINT32	extenderCurrent = 8;
	length = strlen(name);

	if (strcmp(name, "..") == 0 || strcmp(name, ".") == 0)
	{
		return EXT2_SUCCESS;
	}
	else
	{
		for (i = 0; i < length; i++)
		{
			if (name[i] != '.' && !isdigit(name[i]) && !isalpha(name[i])) {
				printf("%c is not valid characte\n", name[i]);
				return EXT2_ERROR;
			}	

			if (name[i] == '.')
			{
				if (extender) {
					printf("reduplication extender('.')\n");
					return EXT2_ERROR;
				}
				extender = 1;
			}
		}

		if (length > EXT2_NAME_LEN || length == 0 || extenderCurrent > 11) {
			printf("wrong length : %u\n", length);
			return EXT2_ERROR;
		}
	}

	return EXT2_SUCCESS;
}


// null : 새로운 entry가 들어갈 자리를 포함하는 entry의 location 정보
// name : name에 해당하는 entry의 location 정보
// 둘다 못찾았으면 ERROR 리턴 (어차피 entry의 끝은 i_block이 0인것을 검사해서 확인할 수 있음) 
int find_entry_at_block(const BYTE* block, const BYTE* formattedName, EXT2_DIR_ENTRY* dir_entry, UINT32* offset)
{
	EXT2_DIR_ENTRY* entry;
	BYTE *block_offset, *block_end;
	UINT32 real_record_len, hole_len;
	UINT32 loc_offset, cmp_length;
	block_offset = block;
	loc_offset = 0;
	//parent->fs->sb.log_block_size 형태로 가져올 수 있도록 수정해야 함
	block_end = block_offset + 1024;

	while (block_offset != block_end)

	{
		entry = (EXT2_DIR_ENTRY *)block_offset;
		real_record_len = GET_RECORD_LEN(entry);

		if (formattedName == NULL) // 빈자리 찾기
		{

			hole_len = entry->record_len - real_record_len;
			if ((hole_len > 0) && ((GET_RECORD_LEN(dir_entry)) <= hole_len))
			{
				*offset = loc_offset;

				return EXT2_SUCCESS;
			}
		}
		else // 엔트리 찾기
		{

			cmp_length = MAX((size_t)(entry->name_len), strlen(formattedName));
			if (memcmp(entry->name, formattedName, cmp_length) == 0) 
			{
				memcpy(dir_entry, entry, real_record_len);
				printf("lookup entry inode : %u\n", entry->inode);
				*offset = loc_offset;
				return EXT2_SUCCESS;
			}
		}

		block_offset += entry->record_len;
		loc_offset += entry->record_len;
	}

	return EXT2_ERROR;
}

int lookup_entry(EXT2_FILESYSTEM* fs, const int inode_num, const char* formattedName, EXT2_NODE* ret)
{
	// dir 만드는 경우..모든 그룹을 다 돌아야됨.
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	int i_block_index;
	INODE inode;
	UINT32 byte_per_block = 1024 << LOG_BLOCK_SIZE;
	int result;

	get_inode(fs, inode_num, &inode);
	// inode의 i_block을 돌아서 
	for (i_block_index = 0; i_block_index < 15; i_block_index++)
	{	
		// inode.i_block[i_block_index] 번째 block, block 버퍼에 저장
		UINT32 block_num = inode.i_block[i_block_index];
		EXT2_ENTRY_LOCATION loc;
		get_block_location(fs, block_num, &loc);
		read_disk_per_block(fs, loc.group, loc.block, block);
		
		// && ~ : i_block에 block이 할당된 경우
		if (i_block_index < 12 && inode.i_block[i_block_index])
		{
			result = get_entry_loc_at_block(block, formattedName, inode.i_block[i_block_index], ret);
			if (result == EXT2_ERROR) continue;
			else
			{
				//printf("'%s' file is already exist.\n", formattedName);
				return result;
			} 
		}
		else if (i_block_index >= 12 && inode.i_block[i_block_index])
		{
			int block_offset_1, block_offset_2, block_offset_3;
			int max_block_offset = byte_per_block / sizeof(int *);
			BYTE file_block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
			BYTE file_block_2[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
			BYTE file_block_3[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];

			switch(i_block_index)
			{
				case 12: // 단일 간접
					for (block_offset_1 = 0; block_offset_1 < max_block_offset ; block_offset_1++)
					{
						*(int *)( block[block_offset_1] ) = file_block;

						result = get_entry_loc_at_block(block, formattedName, inode.i_block[i_block_index], ret);
						if (result = EXT2_ERROR) continue;
						else return result;
					}
					break;
				case 13: // 이중 간접
					for (block_offset_2 = 0; block_offset_2 < max_block_offset ; block_offset_2++)
					{
						*(int *)( block[block_offset_2] ) = file_block_2;

						for (block_offset_1 = 0; block_offset_1 < max_block_offset ; block_offset_1++)
						{
							*(int *)( block[block_offset_1] ) = file_block;

							result = get_entry_loc_at_block(block, formattedName, inode.i_block[i_block_index], ret);
							if (result = EXT2_ERROR) continue;
							else return result;
						}
					}
					break;
				case 14: // 삼중 간접
					for (block_offset_3 = 0; block_offset_3 < max_block_offset ; block_offset_3++)
					{
						*(int *)( block[block_offset_3] ) = file_block_3;
						for (block_offset_2 = 0; block_offset_2 < max_block_offset ; block_offset_2++)
						{
							*(int *)( block[block_offset_2] ) = file_block_2;

							for (block_offset_1 = 0; block_offset_1 < max_block_offset ; block_offset_1++)
							{
								*(int *)( block[block_offset_1] ) = file_block;
						
								result = get_entry_loc_at_block(block, formattedName, inode.i_block[i_block_index], ret);
								if (result = EXT2_ERROR) continue;
								else return result;
							}
						}
					}
					break;
			} // switch문 종료	
		}
	}
	return EXT2_ERROR;
}

int get_entry_loc_at_block(const unsigned char *block, const unsigned char *formattedName, UINT32 block_num, EXT2_NODE* ret)
{
	int result;
	UINT32 offset;

	result = find_entry_at_block(block, formattedName, &ret->entry, &offset);
	// success 나오면 파일 있다는 거 -> find_entry_on_root 도 success
	// -1 나오면 다음 블록도 뒤져야댐 -> for문 계속 돌려
	// 왜냐면 마지막 엔트리까지 닿았다가 앞에 엔트리들 다삭제된 걸 수도 있으니깐.
	// -2 나오면 name에 null넣은 경우만 해당하는데, 빈자리가 블럭 마지막 디렉토리 엔트리에 있다는 의미.

	get_block_location(ret->fs, block_num, &ret->location);
	ret->location.offset = offset;

	printf("location : %u, %u, %u\n", ret->location.group, ret->location.block ,ret->location.offset);
	
	return result;
}

/*
int find_entry_on_data(EXT2_FILESYSTEM* fs, INODE first, const BYTE* formattedName, EXT2_NODE* ret)
{
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	
	
	return EXT2_ERROR;
}
*/

int read_root_sector(EXT2_FILESYSTEM* fs, EXT2_DIR_ENTRY *root)
{
	root->file_type = EXT2_FT_DIR;
	root->inode = 2;
	root->name_len = strlen(VOLUME_LABLE);
	memcpy(root->name, VOLUME_LABLE, root->name_len);
	root->record_len = GET_RECORD_LEN(root);

	printf("root record len : %u\n", root->record_len);
	return EXT2_SUCCESS;
}

int ext2_create(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	if ((parent->fs->gd.free_inodes_count) == 0) return EXT2_ERROR;

	UINT32 inode;
	BYTE name[EXT2_NAME_LEN] = { 0, };
	int result;
	BYTE name_length;

	/* 형식에 맞게 name 수정*/
	strcpy(name, entryName);
	if (format_name(parent->fs, name) == EXT2_ERROR) return EXT2_ERROR;

	ZeroMemory(retEntry, sizeof(EXT2_NODE));

	/* ret entry에 fs 등록 */
	retEntry->fs = parent->fs;

	/* parent의 dir entry에 name 파일 있는지 확인 */
	inode = parent->entry.inode;
	if ((result = lookup_entry(parent->fs, inode, name, retEntry)) == EXT2_SUCCESS) return EXT2_ERROR;
	else if (result == -2) return EXT2_ERROR;


	/* ret entry의 dir entry에 name_len, file_type, record_len 등록 */
	name_length = strlen(name);
	retEntry->entry.name_len = name_length;
	memcpy(retEntry->entry.name, name, name_length);
	retEntry->entry.file_type = EXT2_FT_REG_FILE;
	retEntry->entry.record_len = GET_RECORD_LEN(&(retEntry->entry));

	/* parent 에 retEntry 삽입 */
	if (insert_entry(inode, retEntry) == EXT2_ERROR) return EXT2_ERROR;
	
	// 원래 써진 것 이상으로 해줘야할 일
	// directory entry에 record_len, name_len, file_type 넣어줘야함
	// ret entry에 location 등록해야함.


	return EXT2_SUCCESS;
}


int get_data_block_at_inode(EXT2_FILESYSTEM *fs, INODE inode, UINT32 number)
{
	return EXT2_ERROR;
}

int ext2_read_superblock(EXT2_FILESYSTEM* fs, EXT2_NODE* root)
{
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 group_descriptor_block = 1; // group descriptor table 시작 block

	if (fs == NULL || fs->disk == NULL)
	{
		WARNING("DISK OPERATIONS : %p\nEXT2_FILESYSTEM : %p\n", fs, fs->disk);
		return EXT2_ERROR;
	}
	
	/* fs에 0번 block group의 super block, group descriptor table 복사 */

	for (int i = 0; i < SECTOR_PER_BLOCK; i++)
	{
		if(fs->disk->read_sector(fs->disk, BOOT_SECTOR_BASE + i, &(block[i * fs->disk->bytes_per_sector]))== EXT2_ERROR) {
			PRINTF("read_block() function error\n");
			return EXT2_ERROR;
		}
	}

	memcpy(&fs->sb, block, sizeof(EXT2_SUPER_BLOCK));
	read_disk_per_block(fs, 0, group_descriptor_block, block);
	memcpy(&fs->gd, block, sizeof(EXT2_GROUP_DESCRIPTOR));
	
	/* super block인지 확인 */
	if (fs->sb.magic_signature != 0xEF53) 
		return EXT2_ERROR;
	
	/* root 디렉토리로 엔트리 채우기 */
	ZeroMemory(root, sizeof(EXT2_NODE));
	if (read_root_sector(fs, &root->entry) == EXT2_ERROR)
		return EXT2_ERROR;
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
	if (format_name(parent->fs, entryName) == EXT2_ERROR)
		return EXT2_ERROR;
	
	return lookup_entry(parent->fs, parent->entry.inode, entryName, retEntry);
}

int ext2_read_dir(EXT2_NODE* dir, EXT2_NODE_ADD adder, void* list)
{
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	EXT2_ENTRY_LOCATION loc;
	INODE inode_buf;
	UINT32 blk_idx = 0, block_num;

	printf("search dir inode : %u\n", dir->entry.inode);
	get_inode(dir->fs, dir->entry.inode, &inode_buf);

	while (inode_buf.i_block[blk_idx] != 0)
	{
		block_num = inode_buf.i_block[blk_idx];
		printf("dir entry block : %u\n", block_num);

		get_block_location(dir->fs, block_num, &loc);
		read_disk_per_block(dir->fs, loc.group, loc.block, block);

		read_dir_from_block(dir->fs, &loc, block, adder, list);
		blk_idx++;
	}

	return EXT2_SUCCESS;
}

int read_dir_from_block(EXT2_FILESYSTEM* fs, EXT2_ENTRY_LOCATION *loc, BYTE* block, EXT2_NODE_ADD adder, void* list)
{
	EXT2_NODE node;
	EXT2_DIR_ENTRY *entry;
	BYTE *block_offset = block;
	BYTE *block_end = block_offset + (1024 << fs->sb.log_block_size);
	UINT32 real_record_len;

	while (block_offset != block_end)
	{
		entry = (EXT2_DIR_ENTRY *)block_offset;
		block_offset += entry->record_len;

		ZeroMemory(&node, sizeof(EXT2_NODE));
		node.fs = fs;
		node.location = *loc;

		real_record_len = GET_RECORD_LEN(entry);; // 8은 dir_entry에서 name 필드를 제외한 byte 크기
		memcpy(&(node.entry), entry, real_record_len);
		
		adder(fs, list, &node);
	}
	
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
	INODE *inode_buf;
	EXT2_NODE dot_node;
	EXT2_ENTRY_LOCATION loc;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 new_inode;

	if (format_name(parent->fs, entryName) == EXT2_ERROR) {
		printf("entry name is wrong\n");
		return EXT2_ERROR;
	}

	ZeroMemory(retEntry, sizeof(EXT2_NODE));
	retEntry->fs = parent->fs;

	// 임시로 0번 그룹에서 아이노드 할당
	new_inode = alloc_free_inode_in_group(parent->fs, 0);
	if (new_inode == -1){
		printf("alloc inode error\n");
		return EXT2_ERROR;
	}
	printf("new inode : %u\n", new_inode);
	
	get_inode_location(parent->fs, new_inode, &loc);
	read_disk_per_block(parent->fs, loc.group, loc.block, block);
	inode_buf = ((INODE *)block) + loc.offset;
	inode_buf->mode = 0x41A4; // directory, 644
	inode_buf->link_cnt = 2; // ".", ".."
	write_disk_per_block(parent->fs, loc.group, loc.block, block);

	retEntry->entry.inode = new_inode;
	retEntry->entry.file_type = EXT2_FT_DIR;
	retEntry->entry.name_len = strlen(entryName);
	memcpy(retEntry->entry.name, entryName, retEntry->entry.name_len);
	retEntry->entry.record_len = GET_RECORD_LEN(&(retEntry->entry));

	insert_entry(parent->entry.inode, retEntry);



	if (expand_block(parent->fs, new_inode, EXT2_FT_DIR) == EXT2_ERROR) {
		printf("expand block error\n");
		return EXT2_ERROR;
	}

	ZeroMemory(&dot_node, sizeof(EXT2_NODE));
	dot_node.fs = parent->fs;

	dot_node.entry.inode = new_inode;
	dot_node.entry.file_type = EXT2_FT_DIR;
	dot_node.entry.name_len = strlen(".");
	memcpy(dot_node.entry.name, ".", dot_node.entry.name_len);
	dot_node.entry.record_len = GET_RECORD_LEN(&(dot_node.entry));
	insert_entry(new_inode, &dot_node);

	ZeroMemory(&dot_node, sizeof(EXT2_NODE));
	dot_node.fs = parent->fs;

	dot_node.entry.inode = new_inode;
	dot_node.entry.file_type = EXT2_FT_DIR;
	dot_node.entry.name_len = strlen("..");
	memcpy(dot_node.entry.name, "..", dot_node.entry.name_len);
	dot_node.entry.record_len = GET_RECORD_LEN(&(dot_node.entry));
	insert_entry(new_inode, &dot_node);

	return EXT2_SUCCESS;
}

void ext2_print_entry_name(EXT2_NODE *entry) 
{
	BYTE name_buf[EXT2_NAME_LEN + 1] = {0, };
	memcpy(name_buf, entry->entry.name, entry->entry.name_len);
	printf("%s", name_buf);
}

UINT32 scan_bitmap(BYTE *bitmap) {
	UINT32 max_bit = MAX_SECTOR_SIZE * SECTOR_PER_BLOCK * 8; // 1 block size
	UINT32 num, inner_max;

	for(num = 0; num < max_bit; num += 32) { // 32 bit 단위로 훑기
		if (((volatile unsigned int *)bitmap)[num >> 5] != 0xFFFFFFFF) {
			inner_max = num + 32;

			for (;num < inner_max; num++) { //  1 bit 단위로 훑기
				if (!((1UL << (num & 31)) & (((volatile unsigned int *)bitmap)[num >> 5]))) {
					// 해당 bit를 1로 setting 
					(((volatile unsigned int *)bitmap)[num >> 5]) |= (1UL << (num & 31));
					break;
				}
			}
			break;
		}
	}

	return ((num == max_bit) ? -1 : num);
	
}

// 못찾았을 때 -1 리턴, 찾으면 해당 block number 리턴
UINT32 alloc_free_data_block_in_group(EXT2_FILESYSTEM *fs, UINT32 group) {
	BYTE bitmap[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 num;

	read_disk_per_block(fs, group, fs->gd.start_block_of_block_bitmap, bitmap);
	num = scan_bitmap(bitmap);
	if (num == -1) {
		printf("\ncan't fine free block bit in %u group\n", group);
		return -1;
	}
	write_disk_per_block(fs, group, fs->gd.start_block_of_block_bitmap, bitmap);
	return group * fs->sb.block_per_group + num; // block num 은 0 부터 시작
}


void free_data_block(EXT2_FILESYSTEM *fs, UINT32 block_num) {
	BYTE bitmap[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	EXT2_ENTRY_LOCATION loc;
	get_block_location(fs, block_num, &loc);

	read_disk_per_block(fs, loc.group, fs->gd.start_block_of_block_bitmap, bitmap);
	(((volatile unsigned int *)bitmap)[loc.block>>5]) &= (0xFFFFFFFF ^ (1UL << (loc.block & 31)));
	write_disk_per_block(fs, loc.group, fs->gd.start_block_of_block_bitmap, bitmap);
}

UINT32 alloc_free_inode_in_group(EXT2_FILESYSTEM *fs, UINT32 group) {
	BYTE bitmap[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 num;

	read_disk_per_block(fs, group, fs->gd.start_block_of_inode_bitmap, bitmap);
	num = scan_bitmap(bitmap);
	if (num == -1) {
		printf("\ncan't fine free block bit in %u group\n", group);
		return -1;
	}
	write_disk_per_block(fs, group, fs->gd.start_block_of_inode_bitmap, bitmap);
	return group * fs->sb.inode_per_group + num + 1; // inode 은 1 부터 시작
}

void free_inode_in_group(EXT2_FILESYSTEM *fs, UINT32 inode_num) {
	BYTE bitmap[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	
	UINT32 group = (inode_num - 1) / fs->sb.inode_per_group;
	UINT32 offset = (inode_num - 1) % fs->sb.inode_per_group;

	read_disk_per_block(fs, group, fs->gd.start_block_of_block_bitmap, bitmap);
	(((volatile unsigned int *)bitmap)[offset>>5]) &= (0xFFFFFFFF ^ (1UL << (offset & 31)));
	write_disk_per_block(fs, group, fs->gd.start_block_of_block_bitmap, bitmap);
}