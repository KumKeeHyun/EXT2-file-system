#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "shell.h"
#include "disksim.h"

#define SECTOR_SIZE				512 // 2^9
#define NUMBER_OF_SECTORS		131072 //2^17
// disk size : 64MB = 67108864 byte

#define COND_MOUNT				0x01
#define COND_UMOUNT				0x02

typedef struct
{
	char*	name;
	int		( *handler )( int, char** );
	char	conditions;
} COMMAND;

extern void shell_register_filesystem( SHELL_FILESYSTEM* );

void do_shell( void );
void unknown_command( void );
int seperate_string( char* buf, char* ptrs[] );
int shell_cmd_cd( int argc, char* argv[] );
int shell_cmd_exit( int argc, char* argv[] );
int shell_cmd_mount( int argc, char* argv[] );
int shell_cmd_umount( int argc, char* argv[] );
int shell_cmd_touch( int argc, char* argv[] );
int shell_cmd_fill( int argc, char* argv[] );
int shell_cmd_rm( int argc, char* argv[] );
int shell_cmd_ls( int argc, char* argv[] );
int shell_cmd_format( int argc, char* argv[] );
int shell_cmd_df( int argc, char* argv[] );
int shell_cmd_mkdir( int argc, char* argv[] );
int shell_cmd_rmdir( int argc, char* argv[] );
int shell_cmd_mkdirst( int argc, char* argv[] );
int shell_cmd_cat( int argc, char* argv[] );

static COMMAND g_commands[] =
{
	{ "cd",		shell_cmd_cd,		COND_MOUNT	}, // 끝
	{ "exit",	shell_cmd_exit,		0			}, // 끝
	{ "quit",	shell_cmd_exit,		0			}, // 끝
	{ "mount",	shell_cmd_mount,	COND_UMOUNT	}, // 끝
	{ "umount",	shell_cmd_umount,	COND_MOUNT	}, // 끝
	{ "touch",	shell_cmd_touch,	COND_MOUNT	}, // 끝
	{ "fill",	shell_cmd_fill,		COND_MOUNT	},
	{ "rm",		shell_cmd_rm,		COND_MOUNT	}, // 끝
	{ "ls",		shell_cmd_ls,		COND_MOUNT	}, // 끝
	{ "dir",	shell_cmd_ls,		COND_MOUNT	}, // 끝
	{ "format",	shell_cmd_format,	COND_UMOUNT	}, // 끝
	{ "df",		shell_cmd_df,		COND_MOUNT	}, // 끝
	{ "mkdir",	shell_cmd_mkdir,	COND_MOUNT	}, // 끝
	{ "rmdir",	shell_cmd_rmdir,	COND_MOUNT	}, // 끝
	{ "mkdirst",shell_cmd_mkdirst,	COND_MOUNT	}, // 끝
	{ "cat",	shell_cmd_cat,		COND_MOUNT	}
};

static SHELL_FILESYSTEM		g_fs;
static SHELL_FS_OPERATIONS	g_fsOprs;
static SHELL_ENTRY			g_rootDir;
static SHELL_ENTRY			g_currentDir;

// disk를 관리하는 구조체
// disk가 관리하는 sector의 크기, 개수
// disk에서 sector단위로 읽기, 쓰기함수
static DISK_OPERATIONS		g_disk;

// command의 개수
int g_commandsCount = sizeof( g_commands ) / sizeof( COMMAND );
int g_isMounted;

int main( int argc, char* argv[] )
{
	// disk 등록, disk 메모리 할당
	if( disksim_init( NUMBER_OF_SECTORS, SECTOR_SIZE, &g_disk ) < 0 )
	{
		printf( "disk simulator initialization has been failed\n" );
		return -1;
	}

	// file_system 등록
	shell_register_filesystem( &g_fs ); 

	// shell 실행
	do_shell();

	return 0;
}

// 해당명령어가 실행될 수 있는 상태인지 검사, 오류일때 -1 return
// COND_MOUNT  : file_system이 mount되지 않았으면 실행할 수 없음
// COND_UMOUNT : file_system이 이미 mount되었다면 실행할 수 없음
int check_conditions( int conditions )
{
	// conditions & COND_MOUNT : check하려는 명령어의 condition이 COND_MOUNT인 명령어 검사
	// 만약 mount되지 않았다면 오류
	if( conditions & COND_MOUNT && !g_isMounted )
	{
		printf( "file system is not mounted\n" );
		return -1;
	}

	// conditions & COND_UMOUNT : check하려는 명령어의 condition이 COND_UMOUNT인 명령어 검사
	// 만약 이미 mount되어 있다면 오류
	if( conditions & COND_UMOUNT && g_isMounted )
	{
		printf( "file system is already mounted\n" );
		return -1;
	}

	return 0;
}

void do_shell( void )
{
	char buf[1000];
	char* argv[100];
	int argc;
	int i;

	printf( "%s File system shell\n", g_fs.name );

	while( -1 )
	{
		// shell 명령 입력
		printf( "\n[%s/]# ", g_currentDir.name );
		fgets( buf, 1000, stdin );

		// 문자열을 argv[]로 나눔
		argc = seperate_string( buf, argv );

		if( argc == 0 )
			continue;

		// command list를 순회하면서 shell 명령 검색
		for( i = 0; i < g_commandsCount; i++ )
		{
			if( strcmp( g_commands[i].name, argv[0] ) == 0 )
			{
				// 해당 command가 실행될 수 있는 상태인지 검사
				if( check_conditions( g_commands[i].conditions ) == 0 )
					g_commands[i].handler( argc, argv ); 

				break;
			}
		}
		// command list를 끝까지 순회하였는데 command를 찾지 못했으면
		if( argc != 0 && i == g_commandsCount )
			unknown_command();
	}
}

// command list 출력
void unknown_command( void ) 
{
	int i;

	printf( " * " );
	for( i = 0; i < g_commandsCount; i++ )
	{
		if( i < g_commandsCount - 1 )
			printf( "%s, ", g_commands[i].name );
		else
			printf( "%s", g_commands[i].name );
	}
	printf( "\n" );
}

// shell 명령 문자열을 argv[]로 나누기
int seperate_string( char* buf, char* ptrs[] )
{
	char prev = 0;
	int count = 0;

	while( *buf )
	{
		if( isspace( *buf ) )
			*buf = 0;
		else if( prev == 0 )	/* 이전 문자가 '\0'이라면 새로운 문자열 시작 */
			ptrs[count++] = buf;
		
		// buf가 가리키는 곳을 1글자씩 움직이면서 이전 문자의 value를 저장
		prev = *buf++;
	}

	return count;
}

/******************************************************************************/
/* Shell commands...                                                          */
/******************************************************************************/

int shell_cmd_cd( int argc, char* argv[] )
{
	SHELL_ENTRY	newEntry;
	int			result;
	static SHELL_ENTRY	path[256]; // 경로 stack
	static int			pathTop = 0; // stack의 top

	path[0] = g_rootDir; // stack 최하위에 root 디렉토리

	if( argc > 2 )
	{
		printf( "usage : %s [directory]\n", argv[0] );
		return 0;
	}

	if( argc == 1 )
		pathTop = 0;
	else
	{
		if( strcmp( argv[1], "." ) == 0 )
			return 0;
		else if( strcmp( argv[1], ".." ) == 0 && pathTop > 0 )
			pathTop--; // 상위 디렉토리로 이동시 stack에서 pop
		else
		{
			result = g_fsOprs.lookup( &g_disk, &g_fsOprs, &g_currentDir, &newEntry, argv[1] );
			if( result )
			{
				printf( "directory not found\n" );
				return -1;
			}
			else if( !newEntry.isDirectory )
			{
				printf( "%s is not a directory\n", argv[1] );
				return -1;
			}
			path[++pathTop] = newEntry; // stack에 push
		}
	}

	g_currentDir = path[pathTop];

	return 0;
}

// 디스크영역을 시뮬레이션하기 위해 할당받았던 영역을 해제 
int shell_cmd_exit( int argc, char* argv[] )
{
	disksim_uninit( &g_disk );
	_exit( 0 );

	return 0;
}

int shell_cmd_mount( int argc, char* argv[] )
{
	int result;

	if( g_fs.mount == NULL )
	{
		printf( "The mount functions is NULL\n" );
		return 0;
	}

	result = g_fs.mount( &g_disk, &g_fsOprs, &g_rootDir );
	g_currentDir = g_rootDir;

	if( result < 0 )
	{
		printf( "%s file system mounting has been failed\n", g_fs.name );
		return -1;
	}
	else
	{
		printf( "%s file system has been mounted successfully\n", g_fs.name );
		g_isMounted = 1;
	}

	return 0;
}

int shell_cmd_umount( int argc, char* argv[] )
{
	g_isMounted = 0;

	if( g_fs.umount == NULL )
		return 0;

	// 동적할당해서 사용하던 영역(file_system에 관련된)들을 모두 해제
	g_fs.umount( &g_disk, &g_fsOprs );
	return 0;
}

int shell_cmd_touch( int argc, char* argv[] )
{
	SHELL_ENTRY	entry;
	int			result;

	if( argc < 2 )
	{
		printf( "usage : touch [files...]\n" );
		return 0;
	}

	result = g_fsOprs.fileOprs->create( &g_disk, &g_fsOprs, &g_currentDir, argv[1], &entry );

	if( result )
	{
		printf( "create failed\n" );
		return -1;
	}

	return 0;
}

int shell_cmd_fill( int argc, char* argv[] )
{
	SHELL_ENTRY	entry;
	char*		buffer;
	char*		tmp;
	int			size;
	int			result;

	if( argc != 3 )
	{
		printf( "usage : fill [file] [size]\n" );
		return 0;
	}

	sscanf( argv[2], "%d", &size );

	result = g_fsOprs.fileOprs->create( &g_disk, &g_fsOprs, &g_currentDir, argv[1], &entry );
	if( result )
	{
		printf( "create failed\n" );
		return -1;
	}

	buffer = ( char* )malloc( size + 13 );
	tmp = buffer;
	while( tmp < buffer + size )
	{
		memcpy( tmp, "Can you see? ", 13 );
		tmp += 13;
	}
	g_fsOprs.fileOprs->write( &g_disk, &g_fsOprs, &g_currentDir, &entry, 0, size, buffer );
	free( buffer );

	return 0;
}

int shell_cmd_rm( int argc, char* argv[] )
{
	int i;

	if( argc < 2 )
	{
		printf( "usage : rm [files...]\n" );
		return 0;
	}

	for( i = 1; i < argc; i++ )
	{
		if( g_fsOprs.fileOprs->remove( &g_disk, &g_fsOprs, &g_currentDir, argv[i] ) )
			printf( "cannot remove file\n" );
	}

	return 0;
}

int shell_cmd_ls( int argc, char* argv[] )
{
	SHELL_ENTRY_LIST		list;
	SHELL_ENTRY_LIST_ITEM*	current;

	if( argc > 2 )
	{
		printf( "usage : %s [path]\n", argv[0] );
		return 0;
	}

	init_entry_list( &list );
	if( g_fsOprs.read_dir( &g_disk, &g_fsOprs, &g_currentDir, &list ) )
	{
		printf( "Failed to read_dir\n" );
		return -1;
	}

	current = list.first;

	// shell_entry_list 출력
	printf( "[File names] [D] [File sizes]\n" );
	while( current )
	{
		printf( "%-12s  %1d  %12d\n",
				current->entry.name, current->entry.isDirectory, current->entry.size );
		current = current->next;
	}
	printf( "\n" );

	release_entry_list( &list );
	return 0;
}

int shell_cmd_format( int argc, char* argv[] )
{
	int		result;
	char *param = NULL;

	if( argc >= 2 ) 
	{
		param = argv[1];
	}

	result = g_fs.format( &g_disk, param );
	
	if( result < 0 )
	{
		printf( "%s formatting is failed\n", g_fs.name );
		return -1;
	}

	printf( "disk has been formatted successfully\n" );
	return 0;
}

double get_percentage( unsigned int number, unsigned int total )
{
	return ( ( double )number ) / total * 100.;
}


// sector 사용량 출력(free_cluster_list.count 사용)
int shell_cmd_df( int argc, char* argv[] )
{
	unsigned int used, total;
	int result;

	g_fsOprs.stat( &g_disk, &g_fsOprs, &total, &used );

	printf( "free sectors : %u(%.2lf%%)\tused sectors : %u(%.2lf%%)\ttotal : %u\n",
			total - used, get_percentage( total - used, g_disk.number_of_sectors ),
		   	used, get_percentage( used, g_disk.number_of_sectors ),
		   	total );

	return 0;
}

int shell_cmd_mkdir( int argc, char* argv[] )
{
	SHELL_ENTRY	entry;
	int result;

	if( argc != 2 )
	{
		printf( "usage : %s [name]\n", argv[0] );
		return 0;
	}

	result = g_fsOprs.mkdir( &g_disk, &g_fsOprs, &g_currentDir, argv[1], &entry );

	if( result )
	{
		printf( "cannot create directory\n" );
		return -1;
	}

	return 0;
}

int shell_cmd_rmdir( int argc, char* argv[] )
{
	int result;

	if( argc != 2 )
	{
		printf( "usage : %s [name]\n", argv[0] );
		return 0;
	}

	result = g_fsOprs.rmdir( &g_disk, &g_fsOprs, &g_currentDir, argv[1] );

	if( result )
	{
		printf( "cannot remove directory\n" );
		return -1;
	}

	return 0;
}

// 전달인자만큼 mkdir 반복
int shell_cmd_mkdirst( int argc, char* argv[] )
{
	SHELL_ENTRY	entry;
	int		result, i, count;
	char	buf[10];

	if( argc != 2 )
	{
		printf( "usage : %s [count]\n", argv[0] );
		return 0;
	}

	sscanf( argv[1], "%d", &count );
	for( i = 0; i < count; i++ )
	{
		sprintf( buf, "%d", i );
		result = g_fsOprs.mkdir( &g_disk, &g_fsOprs, &g_currentDir, buf, &entry );

		if( result )
		{
			printf( "cannot create directory\n" );
			return -1;
		}
	}

	return 0;
}

int shell_cmd_cat( int argc, char* argv[] )
{
	SHELL_ENTRY	entry;
	char		buf[1025] = { 0, };
	int			result;
	int 		n;
	unsigned long	offset = 0;

	if( argc != 2 )
	{
		printf( "usage : %s [file name]\n", argv[0] );
		return 0;
	}

	result = g_fsOprs.lookup( &g_disk, &g_fsOprs, &g_currentDir, &entry, argv[1] );
	if( result )
	{
		printf( "%s lookup failed\n", argv[1] );
		return -1;
	}

	while( (n = g_fsOprs.fileOprs->read( &g_disk, &g_fsOprs, &g_currentDir, &entry, offset, 1024, buf )) > 0 )
	{
		printf( "%s", buf );
		offset += n;
		memset( buf, 0, sizeof( buf ) );
	}
	printf( "\n" );
}