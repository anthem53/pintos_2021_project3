#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "threads/malloc.h"
#include "filesys/off_t.h"
#include <stdio.h>
#include <stddef.h>
#include <hash.h>

// supplemental page table entry
// 편의상 page라고 설정
struct page
{
  uint32_t va;
  bool isLoaded;
  struct hash_elem elem;
  struct thread* owner;

  // variables for load_segment
  struct file* file;
  off_t ofs;
  uint8_t *upage;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;

  // variables for sys_mmap
  int mapid;
  int fd;

  // variables for swap table
  bool is_swapped;
  int swap_index;
};
/*
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable); */

struct page* page_init(uint32_t addr, int _mapid);
void page_init_segment(struct page* p, struct file *file, off_t ofs,
   uint8_t *upage,  uint32_t read_bytes, uint32_t zero_bytes,
   bool writable);
struct page* page_search(void * addr);
unsigned page_hash_func(const struct hash_elem *e, void *aux);
bool page_less_func (const struct hash_elem *a, const struct
hash_elem *b, void *aux);
void page_free(struct page* p);

#endif
