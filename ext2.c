typedef struct
{
	char*	address;
} DISK_MEMORY;

#include "ext2.h"
#include "ext2_shell.h"
#include "ext2_indirect.h"

#define MIN( a, b )					( ( a ) < ( b ) ? ( a ) : ( b ) )
#define MAX( a, b )					( ( a ) > ( b ) ? ( a ) : ( b ) )

#define GET_RECORD_LEN(entry) 		((entry)->name_len + 8)

#define FILL_ENTRY(entry, _inode, _name, _type) \
(entry)->inode = _inode; \
(entry)->file_type = _type; \
(entry)->name_len = strlen(_name); \
memcpy((entry)->name, _name, (entry)->name_len); \
(entry)->record_len = GET_RECORD_LEN((entry))

int ext2_write(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	DWORD	current_offset, current_block;
	DWORD	block_number; // 실제 블록 넘버말고 논리적인 블록 순서
	DWORD	start_block_number;
	DWORD	read_end;
	DWORD	block_offset = 0;

	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 byte_per_block = 1024 << LOG_BLOCK_SIZE; // MAX_SECTOR_SIZE * SECTOR_PER_BLOCK
	EXT2_DIR_ENTRY *entry = &file->entry;
	INODE *inode_ptr;
	EXT2_ENTRY_LOCATION loc;

	read_end = offset + length;
	current_offset = offset;
	start_block_number = offset / byte_per_block;
	block_number = read_end / byte_per_block;

	// start_block_number 에서부터 block_number까지 할당 안돼있으면 할당해줘야함.
	for (int i = start_block_number ; i <= block_number ; i++)
	{ 
		expand_block(file->fs, entry->inode, i, 0, EXT2_FT_REG_FILE);
	}

	while (current_offset < read_end)
	{
		DWORD copy_length;

		current_block = current_offset / byte_per_block;
		block_offset = current_offset % byte_per_block;

		copy_length =  MIN(byte_per_block - block_offset, read_end - current_offset);

		// block 읽어와서 copy_length만큼 쓴 다음 그거 write
		if (copy_length != byte_per_block) {
			if (read_data_indirect(file->fs, entry->inode, current_block, block) == EXT2_ERROR)
			{
				printf("read_data_by_logical_block_num() function error.\n");
				return EXT2_ERROR;
			}
		}
		
		memcpy(&block[block_offset], buffer, copy_length);
		if( write_data_indirect(file->fs, entry->inode, current_block, block) == EXT2_ERROR)
		{
			printf("write_data_by_logical_block_num() function error.\n");
			return EXT2_ERROR;
		}
		
		get_inode_location(file->fs, entry->inode, &loc);
		read_disk_per_block(file->fs, loc.group, loc.block, block); // block 버퍼 재활용

		inode_ptr = ((INODE*)block) + loc.offset;
		inode_ptr->size += copy_length;

		buffer += copy_length;
		current_offset += copy_length;
		write_disk_per_block(file->fs, loc.group, loc.block, block);
	}

	return current_offset - offset;
}

int ext2_read(EXT2_NODE* file, unsigned long offset, unsigned long length, const char* buffer)
{
	DWORD	current_offset;
	DWORD	block_number; // 실제 블록 넘버말고 논리적인 블록 순서
	DWORD	read_end;
	DWORD	block_offset = 0;

	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 byte_per_block = 1024 << LOG_BLOCK_SIZE;
	EXT2_DIR_ENTRY *entry = &file->entry;
	INODE inode;
	int i_block_index;

	get_inode(file->fs, entry->inode, &inode);
	read_end = MIN(offset + length, inode.size);
	current_offset = offset;
	block_number = offset / byte_per_block;

	while (current_offset < read_end)
	{
		DWORD copy_length;

		block_number = current_offset / byte_per_block;
		block_offset = current_offset % byte_per_block;
	
		// block_number 에 따라서 data block 가져오기 
		if (read_data_indirect(file->fs, entry->inode, block_number , block) == EXT2_ERROR)
		{
			printf("read_data_by_logical_block_num() function error.\n");
			return EXT2_ERROR;
		}

		copy_length =  MIN(byte_per_block - block_offset, read_end - current_offset);

		memcpy(buffer, &block[block_offset], copy_length);

		buffer += copy_length;
		current_offset += copy_length;
	}

	return current_offset - offset;
}

// 논리적인 블럭 번호를 통해 블럭을 검색, 읽음
int read_data_indirect(EXT2_FILESYSTEM* fs, const int inode_num, UINT32 logic_blk , BYTE* block_buf)
{
	INODE inode;
	Indirect_Location i_loc;
	RW_Argv argv;
	int result;

	argv.block = block_buf;

	get_inode(fs, inode_num, &inode);

	if (get_indirect_location(fs, logic_blk, &i_loc) == EXT2_ERROR) {
		printf("wrong block num\n");
		return EXT2_ERROR;
	}

	switch (i_loc.i_blk)
	{
	case 12:
		result = rw_indirect_func(fs, 1, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_read, &argv);
		break;
	case 13:
		result = rw_indirect_func(fs, 2, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_read, &argv);
		break;
	case 14:
		result = rw_indirect_func(fs, 3, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_read, &argv);
		break;
	default:
		result = rw_indirect_func(fs, 0, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_read, &argv);
		break;
	}
	
	return result;
}

// 논리적인 블럭 번호를 통해 블럭을 검색, 씀
int write_data_indirect(EXT2_FILESYSTEM* fs, const int inode_num, UINT32 logic_blk , BYTE* block_buf)
{
	INODE inode;
	Indirect_Location i_loc;
	RW_Argv argv;
	int result;

	argv.block = block_buf;

	get_inode(fs, inode_num, &inode);

	if (get_indirect_location(fs, logic_blk, &i_loc) == EXT2_ERROR) {
		printf("wrong block num\n");
		return EXT2_ERROR;
	}

	switch (i_loc.i_blk)
	{
	case 12:
		result = rw_indirect_func(fs, 1, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_write, &argv);
		break;
	case 13:
		result = rw_indirect_func(fs, 2, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_write, &argv);
		break;
	case 14:
		result = rw_indirect_func(fs, 3, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_write, &argv);
		break;
	default:
		result = rw_indirect_func(fs, 0, inode.i_block[i_loc.i_blk], &i_loc, rw_indirect_write, &argv);
		break;
	}
	
	return result;
}

int write_block(DISK_OPERATIONS* disk, BYTE* block, unsigned int start_block)
{
	SECTOR sector_index = start_block * SECTOR_PER_BLOCK + BOOT_SECTOR_BASE;

    for (int i = 0; i < SECTOR_PER_BLOCK; i++)
	{
        if (disk->write_sector(disk, sector_index + i, &(block[i * disk->bytes_per_sector])) == EXT2_ERROR) {
			PRINTF("write_block() function error\n");
			return EXT2_ERROR;
		}
    }
	return EXT2_SUCCESS;
}

int read_block(DISK_OPERATIONS* disk, BYTE* block, unsigned int start_block) 
{
	SECTOR sector_index = start_block * SECTOR_PER_BLOCK + BOOT_SECTOR_BASE;

	for (int i = 0; i < SECTOR_PER_BLOCK; i++)
	{
		if(disk->read_sector(disk, sector_index + i, &(block[i * disk->bytes_per_sector]))== EXT2_ERROR) {
			PRINTF("read_block() function error\n");
			return EXT2_ERROR;
		}
	}
	return EXT2_SUCCESS;
}

int ext2_format(DISK_OPERATIONS* disk)
{
	EXT2_SUPER_BLOCK sb;
	EXT2_GROUP_DESCRIPTOR gd;
	EXT2_GROUP_DESCRIPTOR  gd_another_group;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 byte_per_block = 1024 << LOG_BLOCK_SIZE;
    UINT32 number_of_group;
	UINT32 descriptor_per_block = (1024 << LOG_BLOCK_SIZE) / 32;
	int descriptor_block_index = 0;
	int i, gi, j;

	/* super block 채우기 */
	if (fill_super_block(&sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;
	
	ZeroMemory(block, sizeof(block));
	memcpy(block, &sb, sizeof(sb));

	if (write_block(disk, block, 0) == EXT2_ERROR)
		return EXT2_ERROR; 
	
	/* 0번 descriptor 채우기 */
	if (fill_descriptor_block(&gd, &sb, disk->number_of_sectors, disk->bytes_per_sector) != EXT2_SUCCESS)
		return EXT2_ERROR;

	/* descriptor table 채우기 */

	// 0번 block group과 달리, 1번~ block groups는 inode 예약 영역이 없고, 
	// root block이 없어서 free count 다시 초기화
	number_of_group = disk->number_of_sectors / (sb.sector_per_block * sb.block_per_group);
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
			if (write_block(disk, block, 1 + descriptor_block_index++) == EXT2_ERROR)
				return EXT2_ERROR; 
			ZeroMemory(block, sizeof(block));
		}
	} 
	// 꽉 채우지 못한 마지막 block 써줌
	if (number_of_group % descriptor_per_block != 0)
	{
		if (write_block(disk, block, 1 + descriptor_block_index) == EXT2_ERROR)
				return EXT2_ERROR;
	}

	/* block bitmap 채우기 */
	ZeroMemory(block, sizeof(block));

	for (unsigned int i = 0; i < sb.first_meta_bg + 1; i++) {
		(((volatile unsigned int *) block)[i >> 5]) |= (1UL << (i & 31));
	}
	if (write_block(disk,block, gd.start_block_of_block_bitmap) == EXT2_ERROR)
		return EXT2_ERROR;

	/* inode bitmap 채우기 */
	ZeroMemory(block, sizeof(block));

	block[0] = 0xff; // 8개
	block[1] = 0x03; // 2개  inode 예약 영역 10개 잡아줌

	if (write_block(disk, block, gd.start_block_of_inode_bitmap) == EXT2_ERROR)
		return EXT2_ERROR;

	/* inode table 채우기 */
	ZeroMemory(block, sizeof(block));
	
	for (i = gd.start_block_of_inode_table; i < sb.first_meta_bg; i++)
	{
		if (write_block(disk, block, i) == EXT2_ERROR)
			return EXT2_ERROR;
	}

	/* 1번째 block group부터 차례로 super block ~ inode table 채움 */
	for (gi = 1; gi < number_of_group; gi++)
	{
		sb.block_group_num = gi;

		/* gi번째 group에 super block 채우기 */
		ZeroMemory(block, sizeof(block));
		memcpy(block, &sb, sizeof(sb));

		if (write_block(disk, block, sb.block_per_group * gi) == EXT2_ERROR)
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
				if (write_block(disk, block, sb.block_per_group * gi + 1 + descriptor_block_index++) == EXT2_ERROR)
					return EXT2_ERROR;
				ZeroMemory(block, sizeof(block));
			}
		} 
		// 꽉 채우지 못한 마지막 block 써줌
		if (number_of_group % descriptor_per_block != 0) 
		{
			if (write_block(disk, block, sb.block_per_group * gi + 1 + descriptor_block_index) == EXT2_ERROR)
				return EXT2_ERROR;
		}

		/* gi번째 group에 block bitmap 채우기 */
		ZeroMemory(block, sizeof(block));
		
		for (unsigned int i = 0; i < sb.first_meta_bg; i++) {
			(((volatile unsigned int *) block)[i >> 5]) |= (1UL << (i & 31));
		}
		
		if (write_block(disk, block, sb.block_per_group * gi + gd.start_block_of_block_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;

		/* gi번째 group에 inode bitmap 채우기 */
		ZeroMemory(block, sizeof(block));

		if (write_block(disk, block, sb.block_per_group * gi + gd.start_block_of_inode_bitmap) == EXT2_ERROR)
			return EXT2_ERROR;

		/* gi번째 group에 inode table 채우기 */
		ZeroMemory(block, sizeof(block));

		for (i = sb.block_per_group * gi + gd.start_block_of_inode_table; i < sb.block_per_group * gi + sb.first_meta_bg; i++)
		{
			if (write_block(disk, block, i) == EXT2_ERROR)
				return EXT2_ERROR;
		}

	}

	PRINTF("max inode count                : %u\n", sb.max_inode_count);
	PRINTF("total block count              : %u\n", sb.block_count);
	PRINTF("byte size of inode             : %u\n", sb.inode_size);
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
    sb->inode_per_group = inode_per_group;
	sb->mount_cnt = 0;
	sb->max_mount_cnt = 0xFFFF;
    sb->magic_signature = 0xEF53;
    sb->state = 1;
    sb->errors = 0;
	sb->check_interval = 0;
	sb->creator_OS = 0; // linux
	sb->major_version = 0; // inode 크기 고정
	sb->first_ino = 11; 
	sb->inode_size = 128;
	sb->block_group_num = 0;

	// 책에 있는 것 그대로
	sb->feature_compat = 0x24; 
	sb->feature_incompat = 0x02 ; 
	sb->feature_read_only_compat = 0x01;

	sb->sector_per_block = sector_per_block; 
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

	// set inode
	ZeroMemory(block, sizeof(block));
	INODE *root_inode = (INODE *)block; // 2번 inode
	root_inode++;
	root_inode->mode = 0x41ed; // directory, 755
	root_inode->link_cnt = 2; // ".", ".."
	root_inode->block_cnt = 1;
	root_inode->size = MAX_SECTOR_SIZE * SECTOR_PER_BLOCK;
	root_inode->i_block[0] = root_entry_block;
	write_block(disk, block, inode_table_block);
	//dump_block(disk, sb, inode_table_block);

	// set dir_entry
	// "." entry
	ZeroMemory(block, sizeof(block));
	EXT2_DIR_ENTRY *entry = (EXT2_DIR_ENTRY *)block;
	FILL_ENTRY(entry, 2, ".", EXT2_FT_DIR);

	// ".." entry
	EXT2_DIR_ENTRY *prev_entry = entry;
	entry = (EXT2_DIR_ENTRY *)(block + prev_entry->record_len);
	FILL_ENTRY(entry, 2, "..", EXT2_FT_DIR);
	entry->record_len = (1024 << sb->log_block_size) - prev_entry->record_len;

	write_block(disk, block, root_entry_block);

	return EXT2_SUCCESS;
}

int insert_entry(UINT32 inode_num, EXT2_NODE * retEntry)
{
	INODE inode;
	Indirect_Location i_loc;
	EXT2_NODE new_entry;
	UINT32 i = 0;

	new_entry.fs = retEntry->fs;
	new_entry.entry.name_len = retEntry->entry.name_len;

	get_inode(retEntry->fs, inode_num, &inode);

	// 새로운 entry가 들어가는 위치의 바로 앞에 있는 entry 위치정보를 new_entry->loc에 저장
	if (lookup_entry(retEntry->fs, inode_num, NULL, &new_entry) == EXT2_ERROR) 
	{
		get_indirect_location(retEntry->fs, i, &i_loc);
		while (is_alloced_block(retEntry->fs, &inode, &i_loc) != EXT2_ERROR) {
			get_indirect_location(retEntry->fs, ++i, &i_loc);
		}
		expand_block(retEntry->fs, inode_num, i, 0, EXT2_FT_DIR);
		if (lookup_entry(retEntry->fs, inode_num, NULL, &new_entry) == EXT2_ERROR)
			return EXT2_ERROR;
	}
	retEntry->location = new_entry.location;
	set_entry(retEntry->fs, &new_entry.location, &retEntry->entry);

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

	if (loc->offset == 0 && GET_RECORD_LEN(entry) == 8) // mkdir할 때 첫 entry
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

int set_new_inode(EXT2_FILESYSTEM *fs, UINT32 prefer_group, UINT32 is_dir)
{
	INODE *inode_ptr;
	EXT2_ENTRY_LOCATION loc;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	
	UINT32 new_inode;
	
	new_inode = alloc_free_inode_in_group(fs, prefer_group);
	if (new_inode == -1){
		printf("alloc inode error\n");
		return EXT2_ERROR;
	}

	get_inode_location(fs, new_inode, &loc);
	read_disk_per_block(fs, loc.group, loc.block, block);
	inode_ptr = ((INODE *)block) + loc.offset;
	ZeroMemory(inode_ptr, sizeof(INODE));
	if (is_dir == EXT2_FT_DIR) {
		inode_ptr->mode = 0x41ed; // directory, 755
		inode_ptr->link_cnt = 2; // ".", ".."
		inode_ptr->block_cnt = 1;
		inode_ptr->size = MAX_SECTOR_SIZE * SECTOR_PER_BLOCK;
	}
	else {
		inode_ptr->mode = 0x81A4; // regular, 644
	}
	
	write_disk_per_block(fs, loc.group, loc.block, block);

	return new_inode;
}

UINT32 expand_block(EXT2_FILESYSTEM * fs, UINT32 inode_num, UINT64 blk_idx, UINT32 prefer_group, UINT32 is_dir)
{
	INODE *inode_buf;
	Indirect_Location i_loc;
	EXT2_ENTRY_LOCATION loc;
	UINT32 new_block;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];

	get_inode_location(fs, inode_num, &loc);
	read_disk_per_block(fs, loc.group, loc.block, block);
	inode_buf = ((INODE *)block) + loc.offset;

	if (get_indirect_location(fs, blk_idx, &i_loc) == EXT2_ERROR) {
		printf("wrong block num\n");
		return EXT2_ERROR;
	}
	if (is_alloced_block(fs, inode_buf, &i_loc) == EXT2_SUCCESS) {
		printf("i_block[blk_idx] is full\n");
		return EXT2_ERROR;
	}
	else {
		printf("free i_block!\n");
	}

	new_block = alloc_free_data_block_prefer(fs, prefer_group);
	if (new_block == -1) {
		printf("alloc block error\n");
		return EXT2_ERROR;
	}

	set_new_block(fs, inode_buf, &i_loc, new_block);
	inode_buf->block_cnt++;
	write_disk_per_block(fs, loc.group, loc.block, block);

	ZeroMemory(block, sizeof(block));
	if (is_dir == EXT2_FT_DIR) {
		((EXT2_DIR_ENTRY *)block)->record_len = (MAX_SECTOR_SIZE * SECTOR_PER_BLOCK);
		inode_buf->size += MAX_SECTOR_SIZE * SECTOR_PER_BLOCK;
	}
	get_block_location(fs, new_block, &loc);
	write_disk_per_block(fs, loc.group, loc.block, block);

	return EXT2_SUCCESS;
}

int is_alloced_block(EXT2_FILESYSTEM *fs, INODE *inode, Indirect_Location *i_loc)
{
	RW_Argv argv;
	int result;

	argv.block = NULL;

	switch (i_loc->i_blk)
	{
	case 12:
		result = rw_indirect_func(fs, 1, inode->i_block[i_loc->i_blk], i_loc, rw_indirect_check_alloced, &argv);
		break;
	case 13:
		result = rw_indirect_func(fs, 2, inode->i_block[i_loc->i_blk], i_loc, rw_indirect_check_alloced, &argv);
		break;
	case 14:
		result = rw_indirect_func(fs, 3, inode->i_block[i_loc->i_blk], i_loc, rw_indirect_check_alloced, &argv);
		break;
	default:
		result = rw_indirect_func(fs, 0, inode->i_block[i_loc->i_blk], i_loc, rw_indirect_check_alloced, &argv);
		break;
	}

	return result;
}

int set_new_block(EXT2_FILESYSTEM *fs, INODE *inode, Indirect_Location *i_loc, UINT32 new_block)
{
	int result;

	switch (i_loc->i_blk)
	{
	case 12:
		result = expand_indiret(fs, 1, inode->i_block + i_loc->i_blk, i_loc, new_block);
		break;
	case 13:
		result = expand_indiret(fs, 2, inode->i_block + i_loc->i_blk, i_loc, new_block);
		break;
	case 14:
		result = expand_indiret(fs, 3, inode->i_block + i_loc->i_blk, i_loc, new_block);
		break;
	default:
		result = expand_indiret(fs, 0, inode->i_block + i_loc->i_blk, i_loc, new_block);
		break;
	}

	return result;
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
	
	//printf("call get inode : %u\n", inode_num);
	
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
				*offset = loc_offset;
				return EXT2_SUCCESS;
			}
		}

		block_offset += entry->record_len;
		loc_offset += entry->record_len;
	}

	return EXT2_ERROR;
}

// indirect function
int lookup_entry(EXT2_FILESYSTEM* fs, const int inode_num, const char* formattedName, EXT2_NODE* ret)
{
	INODE inode;
	int result, i_blk_idx;
	Argv_Lookup_Entry argv;

	argv.name = formattedName;
	argv.ret = ret;
	
	get_inode(fs, inode_num, &inode);

	for (i_blk_idx = 0; i_blk_idx < 15; i_blk_idx++)
	{
		switch (i_blk_idx)
		{
		case 12:
			result = indirect_func(fs, 1, inode.i_block[i_blk_idx], indirect_lookup_entry, &argv);
			break;
		case 13:
			result = indirect_func(fs, 2, inode.i_block[i_blk_idx], indirect_lookup_entry, &argv);
			break;
		case 14:
			result = indirect_func(fs, 3, inode.i_block[i_blk_idx], indirect_lookup_entry, &argv);
			break;
		default:
			result = indirect_func(fs, 0, inode.i_block[i_blk_idx], indirect_lookup_entry, &argv);
			
			break;
		}
		if (result == EXT2_SUCCESS) return result;
	}

	return EXT2_ERROR;
}

int get_entry_loc_at_block(const unsigned char *block, const unsigned char *formattedName, UINT32 block_num, EXT2_NODE* ret)
{
	int result;
	UINT32 offset;

	result = find_entry_at_block(block, formattedName, &ret->entry, &offset);

	get_block_location(ret->fs, block_num, &ret->location);
	ret->location.offset = offset;

	return result;
}

int read_root_sector(EXT2_FILESYSTEM* fs, EXT2_DIR_ENTRY *root)
{
	root->file_type = EXT2_FT_DIR;
	root->inode = 2;
	root->name_len = strlen(VOLUME_LABLE);
	memcpy(root->name, VOLUME_LABLE, root->name_len);
	root->record_len = GET_RECORD_LEN(root);

	return EXT2_SUCCESS;
}

int ext2_create(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	UINT32 inode, new_inode;
	int result;
	BYTE name_length;
	
	// if ((parent->fs->gd.free_inodes_count) == 0) return EXT2_ERROR;
	if (format_name(parent->fs, entryName) == EXT2_ERROR) return EXT2_ERROR;

	ZeroMemory(retEntry, sizeof(EXT2_NODE));
	retEntry->fs = parent->fs;
	inode = parent->entry.inode;
	
	/* parent의 dir entry에 name 파일 있는지 확인 */
	if (lookup_entry(parent->fs, inode, entryName, retEntry) == EXT2_SUCCESS) return EXT2_ERROR;

	new_inode = set_new_inode(parent->fs, 0, EXT2_FT_REG_FILE);
	if (new_inode == -1){
		printf("alloc inode error\n");
		return EXT2_ERROR;
	}

	/* ret entry의 dir entry에 name_len, file_type, record_len 등록 */
	FILL_ENTRY(&(retEntry->entry), new_inode, entryName, EXT2_FT_REG_FILE);

	/* parent 에 retEntry 삽입 */
	if (insert_entry(inode, retEntry) == EXT2_ERROR) 
		return EXT2_ERROR;
	
	return EXT2_SUCCESS;
}

int ext2_remove(EXT2_NODE *file)
{
	if (file->entry.file_type == EXT2_FT_DIR) {
		printf("it is not file\n");
		return EXT2_ERROR;
	}

	remove_entry(file->fs, &(file->location));
	free_inode_and_blocks(file->fs, file->entry.inode);

	return EXT2_SUCCESS;
}

int free_inode_and_blocks(EXT2_FILESYSTEM *fs, UINT32 inode_num)
{
	INODE inode;
	int i_blk_idx;
	Argv_free_block argv;

	get_inode(fs, inode_num, &inode);

	for (i_blk_idx = 0; i_blk_idx < 15; i_blk_idx++) {
		switch (i_blk_idx)
		{
		case 12: 
			indirect_func(fs, 1, inode.i_block[i_blk_idx], indirect_free_block, &argv);
			break;
		case 13: 
			indirect_func(fs, 2, inode.i_block[i_blk_idx], indirect_free_block, &argv);
			break;
		case 14: 
			indirect_func(fs, 3, inode.i_block[i_blk_idx], indirect_free_block, &argv);
			break;
		default:
			indirect_func(fs, 0, inode.i_block[i_blk_idx], indirect_free_block, &argv);
			break;
		}
	}
	free_inode(fs, inode_num);

	return EXT2_SUCCESS;
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
	if ( read_block(fs->disk, block, 0) == EXT2_ERROR)
		return EXT2_ERROR;

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

int ext2_lookup(EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	if (format_name(parent->fs, entryName) == EXT2_ERROR)
		return EXT2_ERROR;
	
	retEntry->fs = parent->fs;
	return lookup_entry(parent->fs, parent->entry.inode, entryName, retEntry);
}

int ext2_read_dir(EXT2_NODE* dir, EXT2_NODE_ADD adder, void* list)
{
	INODE inode;
	UINT32 result, i_blk_idx;
	Argv_Read_Dir argv;

	argv.adder = adder;
	argv.list = list;

	get_inode(dir->fs, dir->entry.inode, &inode);

	for (i_blk_idx = 0; i_blk_idx < 15; i_blk_idx++)
	{
		switch (i_blk_idx)
		{
		case 12:
			result = indirect_func(dir->fs, 1, inode.i_block[i_blk_idx], indirect_read_dir, &argv);
			break;
		case 13:
			result = indirect_func(dir->fs, 2, inode.i_block[i_blk_idx], indirect_read_dir, &argv);
			break;
		case 14:
			result = indirect_func(dir->fs, 3, inode.i_block[i_blk_idx], indirect_read_dir, &argv);
			break;
		default:
			result = indirect_func(dir->fs, 0, inode.i_block[i_blk_idx], indirect_read_dir, &argv);
			
			break;
		}
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

		if (GET_RECORD_LEN(entry) == 8)
			continue;

		ZeroMemory(&node, sizeof(EXT2_NODE));
		node.fs = fs;
		node.location = *loc;

		real_record_len = GET_RECORD_LEN(entry); // 8은 dir_entry에서 name 필드를 제외한 byte 크기
		memcpy(&(node.entry), entry, real_record_len);
		
		adder(fs, list, &node);
	}
	
	return 0;
}

int ext2_mkdir(const EXT2_NODE* parent, const char* entryName, EXT2_NODE* retEntry)
{
	EXT2_NODE dot_node;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	UINT32 new_inode;

	if (format_name(parent->fs, entryName) == EXT2_ERROR) {
		printf("entry name is wrong\n");
		return EXT2_ERROR;
	}

	ZeroMemory(retEntry, sizeof(EXT2_NODE));
	retEntry->fs = parent->fs;

	// 임시로 0번 그룹에서 아이노드 할당
	new_inode = set_new_inode(parent->fs, 0, EXT2_FT_DIR);
	if (new_inode == -1){
		printf("alloc inode error\n");
		return EXT2_ERROR;
	}
	FILL_ENTRY(&(retEntry->entry), new_inode, entryName, EXT2_FT_DIR);
	insert_entry(parent->entry.inode, retEntry);

	if (expand_block(parent->fs, new_inode, 0, 0, EXT2_FT_DIR) == EXT2_ERROR) {
		printf("expand block error\n");
		return EXT2_ERROR;
	}
	ZeroMemory(&dot_node, sizeof(EXT2_NODE));
	dot_node.fs = parent->fs;
	FILL_ENTRY(&(dot_node.entry), new_inode, ".", EXT2_FT_DIR);
	insert_entry(new_inode, &dot_node);

	ZeroMemory(&dot_node, sizeof(EXT2_NODE));
	dot_node.fs = parent->fs;
	FILL_ENTRY(&(dot_node.entry), parent->entry.inode, "..", EXT2_FT_DIR);
	insert_entry(new_inode, &dot_node);

	return EXT2_SUCCESS;
}

int ext2_rmdir(EXT2_NODE *dir)
{
	INODE inode_buf;
	int blk_idx;

	if (dir->entry.file_type != EXT2_FT_DIR)
	{
		printf("it is not directory\n");
		return EXT2_ERROR;
	}	

	get_inode(dir->fs, dir->entry.inode, &inode_buf);

	if (is_empty_dir(dir->fs, &inode_buf) == EXT2_ERROR)
	{
		printf("it has sub entries\n");
		return EXT2_ERROR;
	}
	else {
		printf("empty dir!!\n");
	}

	remove_entry(dir->fs, &(dir->location));
	free_inode_and_blocks(dir->fs, dir->entry.inode);

	return EXT2_SUCCESS;
}

int remove_entry(EXT2_FILESYSTEM *fs, EXT2_ENTRY_LOCATION *loc)
{
	EXT2_DIR_ENTRY *entry, *rm_entry;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	BYTE *block_offset, *rm_offset;

	read_disk_per_block(fs, loc->group, loc->block, block);
	block_offset = block;
	rm_offset = block_offset + loc->offset;
	rm_entry = (EXT2_DIR_ENTRY *)rm_offset;
	entry = (EXT2_DIR_ENTRY *)block_offset;

	if (loc->offset == 0) {
		entry->name_len = 0; // read_dir 에서 GET_RECORD_LEN == 8이 나오도록
	}
	else {
		while (block_offset + entry->record_len != rm_offset) {
			block_offset += entry->record_len;
			entry = (EXT2_DIR_ENTRY *)block_offset;
		}
		//entry->record_len = GET_RECORD_LEN(entry) + rm_entry->record_len;
		entry->record_len += rm_entry->record_len;
	}
	
	write_disk_per_block(fs, loc->group, loc->block, block);

	return EXT2_SUCCESS;
}

int is_empty_dir(EXT2_FILESYSTEM *fs, const INODE *inode)
{
	EXT2_ENTRY_LOCATION loc;
	EXT2_DIR_ENTRY dotdot;
	BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	int blk_idx, temp;
	int check, used;
	check = used = 0;

	for (blk_idx = 0; blk_idx < 15; blk_idx++)
	{
		if (inode->i_block[blk_idx] == 0)
			continue;
			
		switch (blk_idx) {
			case 12: ;
			case 13: ;
			case 14: ;
			default:
				get_block_location(fs, inode->i_block[blk_idx], &loc);
				read_disk_per_block(fs, loc.group, loc.block, block);
				if (find_entry_at_block(block, "..", &dotdot, &temp) == EXT2_SUCCESS) {
					if (dotdot.record_len + temp >= (MAX_SECTOR_SIZE * SECTOR_PER_BLOCK)) // ".." 이 블럭의 마지막 엔트리인 경우
						check++; 
				}
				used++;
		}
	}
	return ((check && (used == 1)) ? EXT2_SUCCESS : EXT2_ERROR);
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

void free_inode(EXT2_FILESYSTEM *fs, UINT32 inode_num) {
	BYTE bitmap[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
	
	UINT32 group = (inode_num - 1) / fs->sb.inode_per_group;
	UINT32 offset = (inode_num - 1) % fs->sb.inode_per_group;

	read_disk_per_block(fs, group, fs->gd.start_block_of_inode_bitmap, bitmap);
	(((volatile unsigned int *)bitmap)[offset>>5]) &= (0xFFFFFFFF ^ (1UL << (offset & 31)));
	write_disk_per_block(fs, group, fs->gd.start_block_of_inode_bitmap, bitmap);
}

UINT32 alloc_free_data_block_prefer(EXT2_FILESYSTEM *fs, UINT32 prefer)
{
	UINT32 num_of_grp = fs->disk->number_of_sectors / (fs->sb.sector_per_block * fs->sb.block_per_group);
	UINT32 result;

	if (0 <= prefer && prefer < num_of_grp) {
		if ((result = alloc_free_data_block_in_group(fs, prefer)) != -1)
			return result;
	}

	for (UINT32 grp = 0; grp < num_of_grp; grp++) {
		if ((result = alloc_free_data_block_in_group(fs, grp)) != -1)
			return result;
	}
	return -1;
}

int ext2_df(EXT2_FILESYSTEM* fs, unsigned int* total_sectors, unsigned int* used_sectors)
{
	*total_sectors = fs->sb.block_count * SECTOR_PER_BLOCK;
	*used_sectors = *total_sectors - (fs->sb.free_block_count * SECTOR_PER_BLOCK);
	
	return EXT2_SUCCESS;
}