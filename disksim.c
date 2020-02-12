#include <stdlib.h>
#include <memory.h>
//#include "fat.h"
#include "disk.h"
#include "disksim.h"

typedef struct
{
	char*	address;
} DISK_MEMORY;

int disksim_read( DISK_OPERATIONS* this, SECTOR sector, void* data );
int disksim_write( DISK_OPERATIONS* this, SECTOR sector, const void* data );

// DISK_OPERATIONS를 초기화
// disk가 관리하는 sector의 크기, 개수
// disk에서 sector단위로 읽기, 쓰기함수
int disksim_init( SECTOR numberOfSectors, unsigned int bytesPerSector, DISK_OPERATIONS* disk )
{
	if( disk == NULL )
		return -1;

	disk->pdata = malloc( sizeof( DISK_MEMORY ) );
	if( disk->pdata == NULL )
	{
		disksim_uninit( disk );
		return -1;
	}

	// disk가 관리할 영역 할당
	( ( DISK_MEMORY* )disk->pdata )->address = ( char* )malloc( bytesPerSector * numberOfSectors );
	if( disk->pdata == NULL )
	{
		disksim_uninit( disk );
		return -1;
	}

	disk->read_sector	= disksim_read;
	disk->write_sector	= disksim_write;
	disk->number_of_sectors	= numberOfSectors;
	disk->bytes_per_sector	= bytesPerSector;

	return 0;
}

// 동적 할당받은 disk->pdata 해제
void disksim_uninit( DISK_OPERATIONS* this )
{
	if( this )
	{
		if( this->pdata )
			free( this->pdata );
	}
}

// disk의 sector위치에 있는 내용을 sector크기만큼 요청받은 data 주소에 복사 
int disksim_read( DISK_OPERATIONS* this, SECTOR sector, void* data )
{
	// disk가 관리하는 sector들의 시작 주소
	char* disk = ( ( DISK_MEMORY* )this->pdata )->address;

	if( sector < 0 || sector >= this->number_of_sectors )
		return -1; 

	// sector 크기만큼 disk의 정보를 data에 복사
	memcpy( data, &disk[sector * this->bytes_per_sector], this->bytes_per_sector );

	return 0;
}

// 요청한 data 주소에 있는 내용을 disk의 sector위치에 있는 주소에 복사
int disksim_write( DISK_OPERATIONS* this, SECTOR sector, const void* data )
{
	char* disk = ( ( DISK_MEMORY* )this->pdata )->address;

	if( sector < 0 || sector >= this->number_of_sectors )
		return -1;

	memcpy( &disk[sector * this->bytes_per_sector], data, this->bytes_per_sector );

	return 0;
}

