#include "vm/page.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
//#include <hash.h>

void page_free(struct page* p)
{
  hash_delete(&thread_current()->spt, &p->elem);
  free(p);
}

struct page* page_init(uint32_t addr, int _mapid)
{
  struct page* p = (struct page*)malloc(sizeof(struct page) * 1);
  p->va = pg_round_down(addr);
  p->mapid = _mapid;
  p->isLoaded = false;
  p->owner = thread_current();
  hash_insert(&( p->owner->spt), &(p->elem) );

  p->is_swapped = false;
  p->swap_index = -1;

  return p;
}

void page_init_segment(struct page* p, struct file *file, off_t ofs, uint8_t *upage,
                       uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT(file != NULL);
  p->file = file;
  p->ofs = ofs;
  p->upage = upage;
  p->read_bytes = read_bytes;
  p->zero_bytes = zero_bytes;
  p->writable = writable;
}

struct page* page_search(void * addr)
{
  struct thread * current = thread_current();
  struct hash *spt = &(current->spt);
  struct hash_iterator hi;

  hash_first (&hi, spt);
  while (hash_next (&hi))
  {
    struct page* p = hash_entry(hash_cur(&hi) ,struct page, elem);
    if(p->va == addr)
      return p;
  }

  return NULL;
}



//unsigned page_hash_func(const struct hash_elem *e, void *aux);
unsigned page_hash_func(const struct hash_elem *e, void *aux)
{
  struct page * p= (struct page * ) hash_entry(e, struct page, elem);
  unsigned result = hash_int((int)p->va);
  return result;
}
bool page_less_func (const struct hash_elem *a, const struct
hash_elem *b, void *aux)
{
  struct page *p1 = (struct page *) hash_entry(a,struct page, elem);
  struct page *p2 = (struct page *) hash_entry(b,struct page, elem);

  return p1->va < p2->va;
}
