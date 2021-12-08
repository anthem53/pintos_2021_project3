#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "threads/malloc.h"
#include "filesys/off_t.h"
#include <stdio.h>
#include <stddef.h>
#include <hash.h>
#include <bitmap.h>
#include "devices/block.h"
#include "vm/frame.h"


struct bitmap* bmp;
struct block* swap_disk;
block_sector_t numSector;

void swap_init();
size_t swap_out(void* ka);
void swap_in(void* ka, size_t index);

#endif
