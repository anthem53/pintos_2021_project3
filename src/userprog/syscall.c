#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/signal.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
struct file* get_file_from_fd(int fd);
bool validate_read(void *p, int size);
bool validate_write(void *p, int size);

static void (*syscall_table[20])(struct intr_frame*) = {
  sys_halt,
  sys_exit,
  sys_exec,
  sys_wait,
  sys_create,
  sys_remove,
  sys_open,
  sys_filesize,
  sys_read,
  sys_write,
  sys_seek,
  sys_tell,
  sys_close,
  sys_mmap,
  sys_munmap
}; // syscall jmp table

void kill_process() {
  send_signal(-1, SIG_WAIT);
  printf ("%s: exit(%d)\n", thread_current()->name, -1);
  thread_exit();
}

void
syscall_init (void)
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_num = validate_read(f->esp, 4) ? *(int*)(f->esp) : -1;

  if(syscall_num < 0 || syscall_num >= 20) {
    kill_process();
  }

  (syscall_table[syscall_num])(f);
}

void sys_mmap (struct intr_frame * f)
{
  int fd, size, length, numPage, i;
  struct file* _file = NULL;
  void* addr;

  if(!validate_read(f->esp + 4, 8)) kill_process();

  fd = *(int*)(f->esp + 4);
  addr = *(void**)(f->esp + 8);

  if(addr != pg_round_down(addr))
  {
    f->eax = -1;
    return;
  }

  if(addr == NULL || addr >= f->esp
    || page_search(pg_round_down(addr)) != NULL)
  {
    f->eax = -1;
    return;
  }

  if(fd < 2)
  {
    f->eax = -1;
    return;
  }

  struct file* file_old = get_file_from_fd(fd);
  if(file_old == NULL)
  {
    f->eax = -1;
    return;
  }
  _file = file_reopen(file_old);


  length = file_length(_file);
  numPage = length / 4096;
  numPage += length % 4096 == 0 ? 0 : 1;
  //printf("[mmap] file length : %d\n",length);
  for(i = 0 ; i < numPage; i++)
  {
    struct page* p = page_init(addr + i*4096, thread_current()->mapid_ref);
    p->fd = fd;
    //printf("[mmap] current mapid_ref : %d \n", p->mapid);
    page_init_segment(p, _file, i * 4096, p->va,
        length > 4096 ? 4096 : length, 4096 - length, true);

    length -= 4096;

    //printf("va: %p\n", p->va);
  }
  f->eax = thread_current()->mapid_ref;
  thread_current()->mapid_ref++;
}

void sys_munmap (struct intr_frame * f)
{
  int _mapid;
  struct thread * current = thread_current();
  struct hash *spt = &(current->spt);
  struct hash_iterator hi;
  struct hash_elem * e;

  bool flag = false;

  int temp_fd;
  struct file* temp_file;

  if(!validate_read(f->esp + 4, 4)) kill_process();
  _mapid = *(int*)(f->esp + 4);

  //if(_mapid >= current->mapid_ref) kill_process();

  hash_first(&hi , spt);
  e = hi.elem;

  do{

    struct page* p = hash_entry(e ,struct page, elem);
    int temp_mapid  = p->mapid;

    e = hash_next(&hi);

    //printf("[munmap] va  : %p\n",p->va);
    //printf("[munmap] p->mapid  : %d\n",p->mapid);
    //printf("[munmap] _mapid  : %d\n",_mapid);
    if(temp_mapid == _mapid)
    {
        void* va = p->va;
        void* ka = pagedir_get_page(thread_current()->pagedir, va);
        struct frame* _frame = frame_search(ka);

        //printf("[munmap] va : %p\n",va);
        //printf("[munmap] ka : %p\n",ka);
        //printf("[munmap] frame : %p\n",_frame);
        if(flag == false)
        {
          flag = true;
          temp_fd = p->fd;
          temp_file = p->file;
        }
        if(_frame != NULL)
        {

          /* File write : frame to file*/
            if (pagedir_is_dirty(p->owner->pagedir, p->va) == true)
            {
                file_write_at(p->file,va,p->read_bytes,p->ofs);
                update_file_from_fd(p->fd);
            }

            frame_free(_frame);
            pagedir_clear_page (p->owner->pagedir, va);

        }
        page_free(p);

    }

  }while ( e != NULL );

  //printf("[munmap] Before sys_close_help \n");
  lock_acquire(&file_lock);
  file_close(temp_file);
  lock_release(&file_lock);
}

/* Reads a byte at user virtual address UADDR.
  UADDR must be below PHYS_BASE.
  Returns the byte value if successful, -1 if a segfault
  occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
  UDST must be below PHYS_BASE.
  Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

void update_file_from_fd(int fd)
{
  struct list_elem *e;
  struct thread *t = thread_current();
  struct fd_elem *fd_elem;

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd == fd)
    {
      struct file* file_old = fd_elem->file_ptr;
      struct file* file_new = file_reopen(file_old);
      file_copy(file_new, file_old);

      lock_acquire(&file_lock);
      file_close(file_old);
      lock_release(&file_lock);

      fd_elem->file_ptr = file_new;
    }
  }
}

struct file* get_file_from_fd(int fd) {

  struct list_elem *e;
  struct thread *t = thread_current();
  struct fd_elem *fd_elem;

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd == fd)
      return fd_elem->file_ptr;
  }
  return NULL;
}

bool validate_read(void *p, int size) {
  int i = 0;
  if(p >= PHYS_BASE || p + size >= PHYS_BASE) return false;
  for(i = 0; i < size; i++) {
    if(get_user(p + i) == -1)
      return false;
  }
  return true;
}

bool validate_write(void *p, int size) {
  int i = 0;
  if(p >= PHYS_BASE || p + size >= PHYS_BASE) return false;
  for(i = 0; i < size; i++) {
    if(put_user(p + i, 0) == false)
      return false;
  }
  return true;
}



// void halt(void)
void sys_halt (struct intr_frame * f UNUSED) {
  shutdown_power_off();
}

// void exit(int status)
void sys_exit (struct intr_frame * f) {
  int status;
  struct thread* current = thread_current();
  if(!validate_read(f->esp + 4, 4)) kill_process();

  status = *(int*)(f->esp + 4);



  struct hash *spt = &(current->spt);
  struct hash_iterator hi;
  struct hash_elem * e;
  struct file* file_old = NULL;
  hash_first(&hi , spt);
  e = hi.elem;

  do{
    struct page* p = hash_entry(e ,struct page, elem);
    e = hash_next(&hi);

    if(p->mapid != -1)
    {
        void* va = p->va;
        if(is_user_vaddr(va) == false)
          continue;

        void* ka = pagedir_get_page(current->pagedir, va);
        struct frame* _frame = frame_search(ka);

        if(file_old != p->file)
        {
          if(file_old != NULL)
          {
            lock_acquire(&file_lock);
            file_close(file_old);
            lock_release(&file_lock);
          }
          file_old = p->file;
        }
        if(_frame != NULL)
        {
            if (pagedir_is_dirty(current->pagedir, p->va) == true)
            {
                file_write_at(p->file,va,p->read_bytes,p->ofs);
                update_file_from_fd(p->fd);
            }
            //frame_free(_frame);
            pagedir_clear_page (current->pagedir, va);
        }
        //page_free(p);
    }
  }while ( e != NULL );

  if(file_old != NULL)
  {
    lock_acquire(&file_lock);
    file_close(file_old);
    lock_release(&file_lock);
  }
  //printf("[munmap] Before sys_close_help \n");


  send_signal(status, SIG_WAIT);
  printf ("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

// pid_t exec(const char *cmd_line)
void sys_exec (struct intr_frame * f) {
  char *cmd_line;
  pid_t pid;
  char *itr;

  if(!validate_read(f->esp + 4, 4)) kill_process();

  cmd_line = *(char**)(f->esp + 4);
  itr = cmd_line;

  if(!validate_read((void*)cmd_line, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }

  pid = process_execute(cmd_line);
  f->eax = pid == -1 ? pid : get_signal(pid, SIG_EXEC);
}

// int wait (pid_t pid)
void sys_wait (struct intr_frame * f) {
  if(!validate_read(f->esp + 4, 4)) kill_process();

  pid_t pid = *(pid_t*)(f->esp + 4);

  f->eax = process_wait(pid);
}

//bool create (const char *file, unsigned initial_size)
void sys_create (struct intr_frame * f) {
  char *name;
  unsigned initial_size;
  char *itr;

  if(!validate_read(f->esp + 4, 8)) kill_process();

  name = *(char **)(f->esp + 4);
  initial_size = *(unsigned*)(f->esp + 8);
  itr = name;

  if(!validate_read((void*)name, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }

  lock_acquire(&file_lock);
  f->eax = filesys_create(name, initial_size);
  lock_release(&file_lock);
}

//bool remove (const char *file)
void sys_remove (struct intr_frame * f) {
  char *name;
  char *itr;

  if(!validate_read(f->esp + 4, 4)) kill_process();

  name = *(char **)(f->esp + 4);
  itr = name;

  if(!validate_read((void*)name, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }

  lock_acquire(&file_lock);
  f->eax = filesys_remove(name);
  lock_release(&file_lock);
}

//int open (const char *file)
void sys_open (struct intr_frame * f) {
  char *name;
  char *itr;
  struct thread *t;
  struct file *file;
  struct list_elem *e;
  struct fd_elem *f_elem;
  struct fd_elem *fd_elem;

  if(!validate_read(f->esp + 4, 4)) kill_process();

  name = *(char **)(f->esp + 4);
  itr = name;

  if(!validate_read((void*)name, 1)) kill_process();

  while(*itr != '\0') {
    itr++;
    if(!validate_read((void*)itr, 1)) kill_process();
  }

  if(itr == name) {
    f->eax = -1;
    return;
  }

  t = thread_current();
  file = filesys_open(name); //if fails, it returns NULL
  f_elem = malloc(sizeof(struct fd_elem));

  if(file == NULL) {
    f->eax = -1;
    return;
  }

  f_elem->fd = 2;
  f_elem->file_ptr = file;

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd > f_elem->fd) {
      e = list_prev(e);
      list_insert(e, &f_elem->elem);
      f->eax = f_elem->fd;
      return;
    }
    f_elem->fd++;
  }
  list_push_back(&t->fd_table, &f_elem->elem);
  f->eax = f_elem->fd;
}

//int filesize (int fd)
void sys_filesize (struct intr_frame * f) {
  int fd;
  struct file *file;

  if(!validate_read(f->esp + 4, 4)) kill_process();

  fd = *(int*)(f->esp + 4);
  file = get_file_from_fd(fd);

  if(file == NULL) f->eax = -1;

  f->eax = file_length(file);
}

//int read (int fd, void *buffer, unsigned size)
void sys_read (struct intr_frame * f) {
  char c;
  unsigned count = 0;
  int fd;
  uint8_t* buffer;
  unsigned size;
  struct file *file;

  if(!validate_read(f->esp + 4, 12)) kill_process();

  fd = *(int*)(f->esp + 4);
  buffer = *(uint8_t**)(f->esp + 8);
  size = *(unsigned*)(f->esp + 12);
  file = get_file_from_fd(fd);

  if(!validate_write(buffer, size)) kill_process();

  if(fd == 0) {
    c = input_getc();
    while(c != '\n' && c != -1 && count < size) {
      if(!put_user(buffer, c)) kill_process();
      buffer++;
      count++;
      c = input_getc();
    }
    f->eax = count;
  }
  else if(fd == 1) {
    f->eax = -1;
  }
  else {
    if(file == NULL) {
      f->eax = -1;
      return;
    }
    lock_acquire(&file_lock);
    f->eax = file_read(file, buffer, size);
    lock_release(&file_lock);
  }
}

//int write (int fd, const void *buffer, unsigned size)
void sys_write (struct intr_frame * f) {
  int fd;
  char* buffer;
  unsigned size;
  struct file *file;

  if(!validate_read(f->esp + 4, 12)) kill_process();

  fd = *(int*)(f->esp + 4);
  buffer = *(char**)(f->esp + 8);
  size = *(unsigned*)(f->esp + 12);
  file = get_file_from_fd(fd);

  if(!validate_read(buffer, size)) kill_process();

  if(fd == 0) {
    f->eax = 0;
  }
  else if(fd == 1) {
    putbuf(buffer, size);
    f->eax = size;
  }
  else {
    if(file == NULL) {
      f->eax = 0;
      return;
    }
    lock_acquire(&file_lock);
    f->eax = file_write (file, buffer, size);
    lock_release(&file_lock);
  }
}

//void seek (int fd, unsigned position)
void sys_seek (struct intr_frame * f) {
  int fd;
  off_t position;
  struct file *file;

  if(!validate_read(f->esp + 4, 8)) kill_process();

  fd = *(int*)(f->esp + 4);
  position = *(int*)(f->esp + 8);
  file = get_file_from_fd(fd);

  if(file == NULL) f->eax = -1;

  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
}

//unsigned tell (int fd)
void sys_tell (struct intr_frame * f) {
  if(!validate_read(f->esp + 4, 4)) kill_process();
  int fd = *(int*)(f->esp + 4);
  struct file *file = get_file_from_fd(fd);
  if(file == NULL)
    f->eax = -1;
  lock_acquire(&file_lock);
  f->eax = file_tell(file);
  lock_release(&file_lock);
}

//void close (int fd)
void sys_close (struct intr_frame * f) {
  int fd;
  struct file *file;
  struct thread *t;

  if(!validate_read(f->esp + 4, 4)) kill_process();

  fd = *(int*)(f->esp + 4);
  file = get_file_from_fd(fd);
  sys_close_help(file, fd);
}

void sys_close_help(struct file* file, int fd)
{
  struct list_elem* e;
  struct thread* t = thread_current();
  struct fd_elem *fd_elem;

  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);

  for (e = list_begin (&t->fd_table); e != list_end (&t->fd_table);
       e = list_next (e))
  {
    fd_elem = list_entry (e, struct fd_elem, elem);
    if(fd_elem->fd == fd) {
      list_remove(e);
      free(fd_elem);
      return;
    }
  }
}
