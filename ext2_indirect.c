#include "ext2_indirect.h"

#define scope(blk_num, start, end) (start <= blk_num && blk_num < end)

// file이 차지하는 블록의 논리적 순서에 위치한 블록의 i_block_index구함
int get_indirect_location(EXT2_FILESYSTEM *fs, UINT64 blk_num, Indirect_Location *i_loc)
{
    UINT64 indir = (1024 << fs->sb.log_block_size) / sizeof(UINT32);
    UINT64 single_end = 12 + indir;
    UINT64 double_end = single_end + indir * indir; 
    UINT64 trible_end = double_end + indir * indir * indir;

    i_loc->i_blk = i_loc->indir_idx[1] = i_loc->indir_idx[2] = i_loc->indir_idx[3] = -1;

	if (scope(blk_num, 0, 12)) {
        i_loc->i_blk = blk_num;
    }
	else if (scope(blk_num, 12, single_end)) {
        i_loc->i_blk = 12;
        i_loc->indir_idx[1] = blk_num - 12;
    } 
	else if (scope(blk_num, single_end, double_end)) {
        i_loc->i_blk = 13;
        i_loc->indir_idx[2] = (blk_num - single_end) / indir;
        i_loc->indir_idx[1] = (blk_num - single_end) % indir;
    }
	else if (scope(blk_num, double_end, trible_end)) {
        i_loc->i_blk = 14;
        i_loc->indir_idx[3] = (blk_num - double_end) / (indir * indir);
        i_loc->indir_idx[2] = ((blk_num - double_end) % (indir * indir)) / indir;
        i_loc->indir_idx[1] = ((blk_num - double_end) % (indir * indir)) % indir;
    }
	else {
        return EXT2_ERROR;
    }

	return EXT2_SUCCESS;
}

// search indirect blocks
int rw_indirect_func(EXT2_FILESYSTEM *fs, int level, UINT32 blk, Indirect_Location *i_loc, generic *f_ptr, void *argv)
{
    int result;

    if (level > MAX_LEVEL || level < 0) {
        printf("level is too high, max_level is %d\n", MAX_LEVEL);
        return EXT2_ERROR;
    }
    if (blk == 0) {
        return EXT2_ERROR;
    }

    if (level) // indirect block 순회
    {
        EXT2_ENTRY_LOCATION loc;
        BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
        UINT32 *indir_blk;

        get_block_location(fs, blk, &loc);
        read_disk_per_block(fs, loc.group, loc.block, block);

        indir_blk = (UINT32 *)block;
        if (indir_blk[i_loc->indir_idx[level]]) {
            result = rw_indirect_func(fs, level-1, indir_blk[i_loc->indir_idx[level]], i_loc, f_ptr, argv);
            if (result == EXT2_SUCCESS) 
                return result;
        }
    }
    else // level == 0, 실제 기능 수행
    {
        ((RW_Argv *)argv)->argv.tag.fs = fs;
        ((RW_Argv *)argv)->argv.tag.blk_num = blk;
        return f_ptr(argv);
    }
    
    return EXT2_ERROR;
}

int rw_indirect_read(void *_argv)
{
    int result;
    RW_Argv *argv;
    EXT2_ENTRY_LOCATION loc;

    argv = (RW_Argv *)_argv;
    get_block_location(argv->argv.tag.fs, argv->argv.tag.blk_num, &loc);
    result = read_disk_per_block(argv->argv.tag.fs, loc.group, loc.block, argv->block);

    return result;
}

int rw_indirect_write(void *_argv)
{
    int result;
    RW_Argv *argv;
    EXT2_ENTRY_LOCATION loc;

    argv = (RW_Argv *)_argv;
    get_block_location(argv->argv.tag.fs, argv->argv.tag.blk_num, &loc);
    result = write_disk_per_block(argv->argv.tag.fs, loc.group, loc.block, argv->block);

    return result;
}

int rw_indirect_check_alloced(void *_argv)
{
    RW_Argv *argv;
    argv = (RW_Argv *)_argv;
    
    return ((argv->argv.tag.blk_num) ? EXT2_SUCCESS : EXT2_ERROR);
}

/*---------------------------------------------------- */

// 능력이 안돼서 expand 전용 함수 만듦
int expand_indiret(EXT2_FILESYSTEM *fs, int level, UINT32 *blk, Indirect_Location *i_loc, UINT32 new_block)
{
    EXT2_ENTRY_LOCATION loc;
    BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
    UINT32 *indir_blk;
    int result;
    UINT32 temp;

    if (level > MAX_LEVEL || level < 0) {
        printf("level is too high, max_level is %d\n", MAX_LEVEL);
        return EXT2_ERROR;
    }

    if (level) {
        if (!(*blk)) {
            temp = alloc_free_data_block_prefer(fs, -1);
            if (temp != -1) {
                ZeroMemory(block, sizeof(block));
                get_block_location(fs, temp, &loc);
                write_disk_per_block(fs, loc.group, loc.block, block);
                *blk = temp;
            }
            else return EXT2_ERROR;
        }

        get_block_location(fs, *blk, &loc);
        read_disk_per_block(fs, loc.group, loc.block, block);
        indir_blk = (UINT32 *)block;
        
        result = expand_indiret(fs, level-1, &(indir_blk[i_loc->indir_idx[level]]), i_loc, new_block);
        if (result == EXT2_SUCCESS) {
            write_disk_per_block(fs, loc.group, loc.block, block);
            return result;
        }
        else {
            free_data_block(fs, temp);
            *blk = 0;
        }
    }
    else {
        *blk = new_block;
        return EXT2_SUCCESS;
    }
    
    return EXT2_ERROR;
}


/*---------------------------------------------------- */


// traversal indirect blocks
int indirect_func(EXT2_FILESYSTEM *fs, int level, UINT32 blk, generic *f_ptr, void *argv) 
{
    int result;

    if (level > MAX_LEVEL || level < 0) {
        printf("level is too high, max_level is %d\n", MAX_LEVEL);
        return EXT2_ERROR;
    }
    if (blk == 0) {
        return EXT2_ERROR;
    }

    if (level) // indirect block 순회
    {
        EXT2_ENTRY_LOCATION loc;
        BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
        UINT32 *indir_blk;
        UINT32 iter;
        UINT32 num_of_indir = (1024 << fs->sb.log_block_size) / sizeof(UINT32);

        get_block_location(fs, blk, &loc);
        read_disk_per_block(fs, loc.group, loc.block, block);

        indir_blk = (UINT32 *)block;
        for (iter = 0; iter < num_of_indir; iter++)
        {
            if (indir_blk[iter]) {
                result = indirect_func(fs, level-1, indir_blk[iter], f_ptr, argv);
                if (result == EXT2_SUCCESS) return result;
            }
        }
    }
    else // level == 0, 실제 기능 수행
    {
        ((Argv *)argv)->tag.fs = fs;
        ((Argv *)argv)->tag.blk_num = blk;
        return f_ptr(argv);
    }
    
    return EXT2_ERROR;
}


/*---------------------------------------------------- */


int indirect_lookup_entry(void *_argv)
{
    int result;
    BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
    EXT2_ENTRY_LOCATION loc;
    Argv_Lookup_Entry *argv;
    
    argv = (Argv_Lookup_Entry *)_argv;
    get_block_location(argv->tag.fs, argv->tag.blk_num, &loc);
    read_disk_per_block(argv->tag.fs, loc.group, loc.block, block);

    result = get_entry_loc_at_block(block, argv->name, argv->tag.blk_num, argv->ret);
    return result;
}

int indirect_read_dir(void *_argv)
{
    int result;
    BYTE block[MAX_SECTOR_SIZE * SECTOR_PER_BLOCK];
    EXT2_ENTRY_LOCATION loc;
    Argv_Read_Dir *argv;
    
    argv = (Argv_Read_Dir *)_argv;
    get_block_location(argv->tag.fs, argv->tag.blk_num, &loc);
    read_disk_per_block(argv->tag.fs, loc.group, loc.block, block);

    result = read_dir_from_block(argv->tag.fs, &loc, block, argv->adder, argv->list);
    return result;
}

int indirect_free_block(void *_argv)
{
    Argv_free_block *argv;
    argv = (Argv_free_block *)_argv;

    free_data_block(argv->tag.fs, argv->tag.blk_num);
    return EXT2_SUCCESS;
}