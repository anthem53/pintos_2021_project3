#include "vm/swap.h"
#include "threads/malloc.h"
#include "filesys/off_t.h"
#include <stdio.h>
#include <stddef.h>
#include <hash.h>
#include <bitmap.h>
#include "devices/block.h"
#include "vm/frame.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"

#define PGSIZE 4096

struct lock swap_lock;

void swap_init()
{
  printf("Call Swap_init() \n");
  swap_disk = block_get_role(BLOCK_SWAP);
  numSector = block_size(swap_disk);
  bmp = bitmap_create(numSector);
  lock_init(&swap_lock);
}

size_t swap_out(void* ka)
{
  lock_acquire(&swap_lock);
  size_t index = bitmap_scan_and_flip(bmp, 0, PGSIZE/BLOCK_SECTOR_SIZE, false);
  size_t i;
  //char temp[BLOCK_SECTOR_SIZE];

  for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
  {
    //memcpy(temp, ka + i * BLOCK_SECTOR_SIZE, BLOCK_SECTOR_SIZE);
    block_write(swap_disk, i + index, ka + i * BLOCK_SECTOR_SIZE);
  }
  printf("[swap_out] index : %d\n", index);
  lock_release(&swap_lock);
  return index;
}

void swap_in(void* ka, size_t index)
{
  size_t i;

  ASSERT(bitmap_all(bmp, index, 8) == true);
  //char temp[BLOCK_SECTOR_SIZE];
  lock_acquire(&swap_lock);
  printf("[swap_in] index : %d\n", index);
  printf("[swap_in] va : %p\n",ka);

  //void *pagedir_get_page (uint32_t *pd, const void *upage);
  void * vaPageAddr = pagedir_get_page(thread_current()->pagedir, ka);
  if(vaPageAddr == NULL)
  {
    printf("[swap_in] No problem\n");
  }
  else
  {
    printf("[swap_in] Serious problem %s\n",vaPageAddr);
  }

  for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
  {
    printf("[swap_in] Before temp\n");
    void * temp =  ka + i * BLOCK_SECTOR_SIZE;
    printf("[swap_in] i: %d\n", i);
    printf("[swap_in] i + index: %d\n", i + index);

    block_read(swap_disk, i + index,temp);
    printf("[swap_in] after block_read\n");
    //memcpy(ka + i*BLOCK_SECTOR_SIZE, temp, BLOCK_SECTOR_SIZE);
    //printf("[swap_in] after memcpy\n");
  }

  bitmap_set_multiple(swap_disk, index, 8 , false);

  lock_release(&swap_lock);
}
