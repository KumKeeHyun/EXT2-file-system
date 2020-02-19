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