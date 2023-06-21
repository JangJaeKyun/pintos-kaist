/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
    ASSERT (sema != NULL);

    sema->value = value;
    list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT (sema != NULL);
    ASSERT (!intr_context ());

    old_level = intr_disable ();
    while (sema->value == 0) {
        list_insert_ordered (&sema->waiters, &thread_current ()->elem, ready_sort, NULL);
        thread_block ();
    }
    sema->value--;
    intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
    enum intr_level old_level;
    bool success;

    ASSERT (sema != NULL);

    old_level = intr_disable ();
    if (sema->value > 0)
    {
        sema->value--;
        success = true;
    }
    else
        success = false;
    intr_set_level (old_level);

    return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT (sema != NULL);

    old_level = intr_disable ();
    if (!list_empty (&sema->waiters)) {
        list_sort(&sema->waiters, ready_sort, NULL);
        thread_unblock (list_entry (list_pop_front (&sema->waiters), struct thread, elem));
    }
    sema->value++;
    preemptive();
    intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
    struct semaphore sema[2];
    int i;

    printf ("Testing semaphores...");
    sema_init (&sema[0], 0);
    sema_init (&sema[1], 0);
    thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++)
    {
        sema_up (&sema[0]);
        sema_down (&sema[1]);
    }
    printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++)
    {
        sema_down (&sema[0]);
        sema_up (&sema[1]);
    }
}
/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
    ASSERT (lock != NULL);

    lock->holder = NULL;
    sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */

// donation list에 모든 요소 삽입하는 코드
// void
// lock_acquire (struct lock *lock) {
//     ASSERT (lock != NULL);
//     ASSERT (!intr_context ());
//     ASSERT (!lock_held_by_current_thread (lock));

//     struct thread *curr = thread_current();
//     if (lock->holder != NULL) { // 이미 lock을 점유하고 있을 경우
//         curr->wait_on_lock = lock;
//         list_insert_ordered(&lock->holder->donations, &curr->donation_elem, donation_sort, NULL);
//         donate_priority(); // 우선순위 조정
//     }
//     sema_down (&lock->semaphore);
//     curr->wait_on_lock = NULL;
//     lock->holder = curr;
// }

void lock_acquire(struct lock *lock)
{
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *curr = thread_current();

	// if the lock is not available
	if (lock->holder != NULL) { 
		curr->wait_on_lock = lock;
		//lock을 잡고있는 스레드의 원래 우선순위보다 큰 경우
		if (curr->priority > lock->holder->origin_priority) {
			// waiters의 값이 처음 입력되는경우 = donation list에도 현재 lock에 대한 값이 없다.
			if (list_empty(&lock->semaphore.waiters)) {
				list_push_back(&lock->holder->donations, &curr->donation_elem); // add current thread into donation list.
			} 
			//waiters에 값이 존재 = donation list에 현재 lock에 대한 값 존재
			// 현재 스레드의 우선순위가 waiters의 가장 높은 우선순위보다 높으면 donation 안에 값을 바꿔줘야한다.
			else if (list_entry(list_front(&lock->semaphore.waiters), struct thread, elem)->priority < curr->priority) {
				struct list_elem *e;
				//donation list를 탐색
				for (e = list_begin(&lock->holder->donations); e != list_end(&lock->holder->donations); e = list_next(e)) {
					struct thread *t = list_entry(e, struct thread, donation_elem);
					// 받아온 락이 wait_on_lock일경우
					if (lock == t->wait_on_lock) {
						list_remove(&t->donation_elem);
						// insert current thread in the donation list before the thread with lower priority
						list_insert_ordered(&t->donations, &curr->donation_elem, donation_sort, NULL);
						break;
					}
				}
			}
			donate_priority();
		}
	}
	sema_down(&lock->semaphore);
	lock->holder = curr;
	curr->wait_on_lock = NULL;
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
    bool success;

    ASSERT (lock != NULL);
    ASSERT (!lock_held_by_current_thread (lock));

    success = sema_try_down (&lock->semaphore);
    if (success)
        lock->holder = thread_current ();
    return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
    ASSERT (lock != NULL);
    ASSERT (lock_held_by_current_thread (lock));

    //현재 스레드가 요청한 엔트리 제거
    remove_with_lock(lock);

    //우선순위 업데이트
    update_priority();

    lock->holder = NULL;
    sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
    ASSERT (lock != NULL);

    return lock->holder == thread_current ();
}
/* One semaphore in a list. */
struct semaphore_elem {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
    ASSERT (cond != NULL);

    list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
    struct semaphore_elem waiter;

    ASSERT (cond != NULL);
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (lock_held_by_current_thread (lock));

    sema_init (&waiter.semaphore, 0);
    list_insert_ordered (&cond->waiters, &waiter.elem, cmp_sem_priority, NULL);
    lock_release (lock);
    sema_down (&waiter.semaphore);
    lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
    ASSERT (cond != NULL);
    ASSERT (lock != NULL);
    ASSERT (!intr_context ());
    ASSERT (lock_held_by_current_thread (lock));

    if (!list_empty (&cond->waiters)) {
        list_sort(&cond->waiters, cmp_sem_priority, NULL); //대기 중에 우선순위가 변경될 가능성이 있으므로 정렬
        sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
    }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
    ASSERT (cond != NULL);
    ASSERT (lock != NULL);

    while (!list_empty (&cond->waiters))
        cond_signal (cond, lock);
}

/*
 * donation list 우선순위 오름차순 정렬
 */
bool donation_sort(const struct list_elem *a, const struct list_elem *b, void *aux) {
    struct thread *da = list_entry(a, struct thread, donation_elem);
    struct thread *db = list_entry(b, struct thread, donation_elem);

    return da->priority > db->priority;
}

/*
 * semaphore_elem -> thread descriptor 획득 후
 * 우선순위 오름차순 정렬
 */
bool cmp_sem_priority(const struct list_elem *a, const struct list_elem *b, void *aux) {
    struct semaphore_elem *sa = list_entry(a, struct semaphore_elem, elem);
    struct semaphore_elem *sb = list_entry(b, struct semaphore_elem, elem);

    struct list *la = &sa->semaphore.waiters;
    struct list *lb = &sb->semaphore.waiters;

    //list_begin() : list의 첫번째 반환
    struct thread *ta = list_entry(list_begin(la), struct thread, elem);
    struct thread *tb = list_entry(list_begin(lb), struct thread, elem);

    return ta->priority > tb->priority;
}

/*
 * Lock을 가진 스레드의 우선순위가 낮을 경우 현재 스레드의 우선순위를 기부하여 높여준다.
 * 이 함수는 항상 현재 스레드는 요청한 락을 기다리는 상태이므로 처음에는 holder가 존재한다.
 */
void donate_priority() {
    struct thread *curr = thread_current();
    struct thread *holder;

    int priority = curr->priority; //요청이 왔다는 것은 현재 스레드가 우선순위가 높다는 의미

    // 현재 스레드의 우선순위 > 현재 스레드가 원하는 Lock을 가진 스레드의 우선순위
    while(curr->wait_on_lock != NULL) {
        holder = curr->wait_on_lock->holder;
        holder->priority = priority;
        curr = holder;
    }
}

/*
 * donation list에서 현재 스레드의 엔트리 제거
 */
void remove_with_lock(struct lock *lock) {
    //현재 스레드의 donations
    struct list *donation_list = &(thread_current()->donations);
    if(list_empty(donation_list)) {
        return;
    }

    struct list_elem *don_elem = list_front(donation_list);
    struct thread *donation_thread;

    while(don_elem != list_tail(donation_list)) {
        donation_thread = list_entry(don_elem, struct thread, donation_elem);
        if(donation_thread->wait_on_lock == lock) { //현재 스레드에서 요청한 엔트리이면
            list_remove(&donation_thread->donation_elem);
        }
        don_elem = list_next(don_elem);
    }
}

/*
 * 우선순위 업데이트
 */
void update_priority() {
    struct thread *curr = thread_current();
    struct list *donations = &(curr->donations);
    if(list_empty(donations)) { //donation이 없으면 원래 우선순위로 set
        curr->priority = curr->origin_priority;
        return;
    }
    //donation 중 우선순위가 가장 높은 값으로 set
    list_sort(donations, donation_sort, NULL);
    curr->priority = list_entry(list_front(donations), struct thread, donation_elem)->priority;
}
