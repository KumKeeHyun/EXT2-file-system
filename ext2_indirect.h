#include "common.h"
#include "types.h"
#include "ext2.h"

#define MAX_LEVEL 3

typedef int (generic) (void *);

// 공통을 쓰이는 전달인자들
// ex) block_num
typedef struct {
    EXT2_FILESYSTEM *fs;
    UINT32 blk_num;
} Tag; 

typedef struct {
    Tag tag;
    // 새로운 함수부터는 여기에 넣고 싶은 엔트리들 추가
} Argv;

// indirect block을 순회하는 함수
int indirect_func(EXT2_FILESYSTEM *fs, int level, UINT32 blk, generic *f_ptr, void *argv);

/*---------------------------------------------------- */

typedef struct {
    int i_blk;
    int indir_idx[4];
} Indirect_Location;

typedef struct {
    Argv argv;
    BYTE *block;
} RW_Argv;

typedef struct {
    Argv argv;
    BYTE *block;
    int is_expand;

    UINT32 new_block;
} RW_Argv_Expand;

int get_indirect_location(EXT2_FILESYSTEM *fs, UINT64 blk_num, Indirect_Location *i_loc);

int rw_indirect_func(EXT2_FILESYSTEM *fs, int level, UINT32 blk, Indirect_Location *i_loc, generic *f_ptr, void *argv);

int rw_indirect_read(void *_argv);

int rw_indirect_write(void *_argv);

int rw_indirect_check_alloced(void *_argv);


/*---------------------------------------------------- */

int expand_indiret(EXT2_FILESYSTEM *fs, int level, UINT32 *blk, Indirect_Location *i_loc, UINT32 new_block);

/*---------------------------------------------------- */

// lookup entry
typedef struct {
    Tag tag;
    const unsigned char *name;
    EXT2_NODE *ret;
} Argv_Lookup_Entry;

int indirect_lookup_entry(void *_argv);


// read dir
typedef struct {
    Tag tag;
    EXT2_NODE_ADD adder;
    void *list;
} Argv_Read_Dir;

int indirect_read_dir(void *_argv);

// free block
typedef struct {
    Tag tag;
} Argv_free_block;

int indirect_free_block(void *_argv);