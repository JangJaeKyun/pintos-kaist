#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

void argument_stack(char **argv, int argc, void **rsp);
struct thread *get_child_process(tid_t child_tid);

// 파일 디스크립터를 위한 함수
int process_add_file(struct file *f);
void process_close_file(int fd);
<<<<<<< HEAD
struct file* process_get_file(int fd);
=======

struct file *process_get_file(int fd);
>>>>>>> 0a9ac2f13419f077f96463dd2f1a26d01ace8b32

#endif /* userprog/process.h */
