#include "ext2_indirect.h"

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