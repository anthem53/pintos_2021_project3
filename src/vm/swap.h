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

void swap_init()
{
  swap_disk = block_get_role(BLOCK_SWAP);
  numSector = block_size(swap_disk);
  bmp = bitmap_create(numSector);
}

size_t swap_out(void* ka)
{
  size_t index = bitmap_scan_and_flip(bmp, 0, PGSIZE/BLOCK_SECTOR_SIZE, false);
  size_t i;
  for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
  {
    char temp[BLOCK_SECTOR_SIZE];
    memcpy(temp, ka + i * BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
    block_write(swap_disk, i + index, temp);
  }
  return index;
}

void swap_in(void* ka, size_t index)
{
  size_t i;
  for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
  {
    char temp[BLOCK_SECTOR_SIZE];
    block_read(swap_disk, i + index, temp);
    memcpy(ka + i*BLOCK_SECTOR_SIZE, temp, BLOCK_SECTOR_SIZE);

    bitmap_flip(swap_disk, i + index);
  }
}

#endif
