#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/thread.h"
#include "vm/page.h"
#include "threads/malloc.h"

/* initialized in threads/init.c */
struct hash frame_table;

int count_ref;

struct frame
{
  uint32_t pa;
  struct page* p_ref;
  struct hash_elem elem;
  struct thread* owner;
  int count;
};


void frame_init(uint32_t addr, struct page* p);
struct frame* frame_search(uint32_t addr);
unsigned frame_hash_func(const struct hash_elem *e, void *aux);
bool frame_less_func (const struct hash_elem *a, const struct
hash_elem *b, void *aux);
void frame_free(struct frame* f);
struct frame * evict();

#endif
