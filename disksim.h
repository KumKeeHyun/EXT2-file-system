#ifndef _DISKSIM_H_
#define _DISKSIM_H_

#include "common.h"

int disksim_init( SECTOR, unsigned int, DISK_OPERATIONS* );
void disksim_uninit( DISK_OPERATIONS* );

#endif
