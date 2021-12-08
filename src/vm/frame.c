#include "vm/frame.h"
#include "threads/vaddr.h"

void frame_free(struct frame* f)
{
  hash_delete(&frame_table, &f->elem);
  palloc_free_page(f->pa);
  free(f);
}

/* invariant
addr : physical address
this function is called inside of install_page */
void frame_init(uint32_t addr, struct page* p)
{
  struct frame* f = (struct frame*)malloc(sizeof(struct frame) * 1);
  f->pa = addr;
  f->p_ref = p;
  f->owner = thread_current();
  f->count = count_ref;
  count_ref++;
  hash_insert(&frame_table, &f->elem);
}

struct frame* frame_search(uint32_t addr)
{
  struct thread * current = thread_current();


  if (addr < 0xc0000000){
    return NULL;
  }

  struct hash_iterator hi;
  hash_first (&hi, &frame_table);
  while (hash_next (&hi))
  {
    struct frame* f = hash_entry(hash_cur(&hi) ,struct frame, elem);
    if(f->pa == addr)
      return f;
  }

  return NULL;
}
//unsigned page_hash_func(const struct hash_elem *e, void *aux);
unsigned frame_hash_func(const struct hash_elem *e, void *aux)
{
  struct frame * f= (struct frame * ) hash_entry(e, struct frame, elem);
  unsigned result = hash_int((int)f->pa);
  return result;
}
bool frame_less_func (const struct hash_elem *a, const struct
hash_elem *b, void *aux)
{
  struct frame *f1 = (struct frame *) hash_entry(a,struct frame, elem);
  struct frame *f2 = (struct frame *) hash_entry(b,struct frame, elem);

  return f1->pa < f2->pa;
}

struct frame * evict()
{
  struct thread * current = thread_current();

  //printf("[frame.c]  Before while  \n");

  struct frame * result = NULL;
  struct hash_iterator hi;
  hash_first (&hi, &frame_table);
  while (hash_next (&hi))
  {
    struct frame* f = hash_entry(hash_cur(&hi) ,struct frame, elem);
    //printf("*****f->p_ref: %p\n", f->p_ref);
    if (is_user_vaddr(f->p_ref->va) == true)
    //if (current == f->owner  && f->p_ref != 0x1 && f->count > 8)
    {
      //printf("[frame.c]  user frame : %p , frame count : %d \n", f ,f->count);
      if(result == NULL || result->count > f->count)
      {
        result = f;
      }
    }
  }

  //printf("[frame.c] evicted frame : %p\n", result);

  return result;
}
