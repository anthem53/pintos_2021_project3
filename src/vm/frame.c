#include "vm/frame.h"


void frame_free(struct frame* f)
{
  hash_delete(&frame_table, &f->elem);
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
  hash_insert(&frame_table, &f->elem);
}

struct frame* frame_search(uint32_t addr)
{
  struct thread * current = thread_current();
  struct hash_iterator hi;

  hash_first(&hi , &frame_table);
  struct hash_elem * e = hi.elem;
  if (addr < 0xc0000000){
    return NULL;
  }
  do{
    struct frame* f = hash_entry(e ,struct frame, elem);
    if(f->pa == addr)
      return f;

    e = hash_next(&hi);
  }while ( e != NULL );

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
