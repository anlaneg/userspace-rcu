/*
 * urcu-qsbr.c
 *
 * Userspace RCU QSBR library
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 * Copyright (c) 2009 Paul E. McKenney, IBM Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * IBM's contributions to this file may be relicensed under LGPLv2 or later.
 */

#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define BUILD_QSBR_LIB
#include "urcu-qsbr-static.h"
/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#include "urcu-qsbr.h"

static pthread_mutex_t urcu_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Global grace period counter.
 */
unsigned long urcu_gp_ctr = RCU_GP_ONLINE;

/*
 * Written to only by each individual reader. Read by both the reader and the
 * writers.
 */
struct urcu_reader_status __thread urcu_reader_status;

/* Thread IDs of registered readers */
#define INIT_NUM_THREADS 4

struct reader_registry {
	pthread_t tid;
	struct urcu_reader_status *urcu_reader_status;
};

#ifdef DEBUG_YIELD
unsigned int yield_active;
unsigned int __thread rand_yield;
#endif

static struct reader_registry *registry;
static int num_readers, alloc_readers;

static void internal_urcu_lock(void)
{
	int ret;

#ifndef DISTRUST_SIGNALS_EXTREME
	ret = pthread_mutex_lock(&urcu_mutex);
	if (ret) {
		perror("Error in pthread mutex lock");
		exit(-1);
	}
#else /* #ifndef DISTRUST_SIGNALS_EXTREME */
	while ((ret = pthread_mutex_trylock(&urcu_mutex)) != 0) {
		if (ret != EBUSY && ret != EINTR) {
			printf("ret = %d, errno = %d\n", ret, errno);
			perror("Error in pthread mutex lock");
			exit(-1);
		}
		poll(NULL,0,10);
	}
#endif /* #else #ifndef DISTRUST_SIGNALS_EXTREME */
}

static void internal_urcu_unlock(void)
{
	int ret;

	ret = pthread_mutex_unlock(&urcu_mutex);
	if (ret) {
		perror("Error in pthread mutex unlock");
		exit(-1);
	}
}

/*
 * synchronize_rcu() waiting. Single thread.
 */
static void wait_for_quiescent_state(void)
{
	struct reader_registry *index;

	if (!registry)
		return;
	/*
	 * Wait for each thread rcu_reader qs_gp count to become 0.
	 */
	for (index = registry; index < registry + num_readers; index++) {
		int wait_loops = 0;

		if (likely(!rcu_gp_ongoing(&index->urcu_reader_status->qs_gp)))
			continue;
	
		index->urcu_reader_status->gp_waiting = 1;
		while (rcu_gp_ongoing(&index->urcu_reader_status->qs_gp)) {
			if (wait_loops++ == RCU_QS_ACTIVE_ATTEMPTS) {
				sched_yield();	/* ideally sched_yield_to() */
				wait_loops = 0;
			} else {
#ifndef HAS_INCOHERENT_CACHES
				cpu_relax();
#else /* #ifndef HAS_INCOHERENT_CACHES */
				smp_mb();
#endif /* #else #ifndef HAS_INCOHERENT_CACHES */
			}
		}
		index->urcu_reader_status->gp_waiting = 0;
	}
}

/*
 * Using a two-subphases algorithm for architectures with smaller than 64-bit
 * long-size to ensure we do not encounter an overflow bug.
 */

#if (BITS_PER_LONG < 64)
/*
 * called with urcu_mutex held.
 */
static void switch_next_urcu_qparity(void)
{
	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr ^ RCU_GP_CTR);
}

void synchronize_rcu(void)
{
	unsigned long was_online;

	was_online = urcu_reader_status.qs_gp;

	/* All threads should read qparity before accessing data structure
	 * where new ptr points to.
	 */
	/* Write new ptr before changing the qparity */
	smp_mb();

	/*
	 * Mark the writer thread offline to make sure we don't wait for
	 * our own quiescent state. This allows using synchronize_rcu() in
	 * threads registered as readers.
	 */
	if (was_online)
		STORE_SHARED(urcu_reader_status.qs_gp, 0);

	internal_urcu_lock();

	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr ^ RCU_GP_ONGOING);

	switch_next_urcu_qparity();	/* 0 -> 1 */

	/*
	 * Must commit qparity update to memory before waiting for parity
	 * 0 quiescent state. Failure to do so could result in the writer
	 * waiting forever while new readers are always accessing data (no
	 * progress).
	 * Ensured by STORE_SHARED and LOAD_SHARED.
	 */

	/*
	 * Wait for previous parity to be empty of readers.
	 */
	wait_for_quiescent_state();	/* Wait readers in parity 0 */

	/*
	 * Must finish waiting for quiescent state for parity 0 before
	 * committing qparity update to memory. Failure to do so could result in
	 * the writer waiting forever while new readers are always accessing
	 * data (no progress).
	 * Ensured by STORE_SHARED and LOAD_SHARED.
	 */

	switch_next_urcu_qparity();	/* 1 -> 0 */

	/*
	 * Must commit qparity update to memory before waiting for parity
	 * 1 quiescent state. Failure to do so could result in the writer
	 * waiting forever while new readers are always accessing data (no
	 * progress).
	 * Ensured by STORE_SHARED and LOAD_SHARED.
	 */

	/*
	 * Wait for previous parity to be empty of readers.
	 */
	wait_for_quiescent_state();	/* Wait readers in parity 1 */

	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr ^ RCU_GP_ONGOING);

	internal_urcu_unlock();

	/*
	 * Finish waiting for reader threads before letting the old ptr being
	 * freed.
	 */
	if (was_online)
		_STORE_SHARED(urcu_reader_status.qs_gp,
			      LOAD_SHARED(urcu_gp_ctr));
	smp_mb();
}
#else /* !(BITS_PER_LONG < 64) */
void synchronize_rcu(void)
{
	unsigned long was_online;

	was_online = urcu_reader_status.qs_gp;

	/*
	 * Mark the writer thread offline to make sure we don't wait for
	 * our own quiescent state. This allows using synchronize_rcu() in
	 * threads registered as readers.
	 */
	smp_mb();
	if (was_online)
		STORE_SHARED(urcu_reader_status.qs_gp, 0);

	internal_urcu_lock();
	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr ^ RCU_GP_ONGOING);
	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr + RCU_GP_CTR);
	wait_for_quiescent_state();
	STORE_SHARED(urcu_gp_ctr, urcu_gp_ctr ^ RCU_GP_ONGOING);
	internal_urcu_unlock();

	if (was_online)
		_STORE_SHARED(urcu_reader_status.qs_gp,
			      LOAD_SHARED(urcu_gp_ctr));
	smp_mb();
}
#endif  /* !(BITS_PER_LONG < 64) */

/*
 * library wrappers to be used by non-LGPL compatible source code.
 */

void rcu_read_lock(void)
{
	_rcu_read_lock();
}

void rcu_read_unlock(void)
{
	_rcu_read_unlock();
}

void *rcu_dereference(void *p)
{
	return _rcu_dereference(p);
}

void *rcu_assign_pointer_sym(void **p, void *v)
{
	wmb();
	return STORE_SHARED(p, v);
}

void *rcu_cmpxchg_pointer_sym(void **p, void *old, void *_new)
{
	wmb();
	return cmpxchg(p, old, _new);
}

void *rcu_xchg_pointer_sym(void **p, void *v)
{
	wmb();
	return xchg(p, v);
}

void *rcu_publish_content_sym(void **p, void *v)
{
	void *oldptr;

	oldptr = _rcu_xchg_pointer(p, v);
	synchronize_rcu();
	return oldptr;
}

void rcu_quiescent_state(void)
{
	_rcu_quiescent_state();
}

void rcu_thread_offline(void)
{
	_rcu_thread_offline();
}

void rcu_thread_online(void)
{
	_rcu_thread_online();
}

static void rcu_add_reader(pthread_t id)
{
	struct reader_registry *oldarray;

	if (!registry) {
		alloc_readers = INIT_NUM_THREADS;
		num_readers = 0;
		registry =
			malloc(sizeof(struct reader_registry) * alloc_readers);
	}
	if (alloc_readers < num_readers + 1) {
		oldarray = registry;
		registry = malloc(sizeof(struct reader_registry)
				* (alloc_readers << 1));
		memcpy(registry, oldarray,
			sizeof(struct reader_registry) * alloc_readers);
		alloc_readers <<= 1;
		free(oldarray);
	}
	registry[num_readers].tid = id;
	/* reference to the TLS of _this_ reader thread. */
	registry[num_readers].urcu_reader_status = &urcu_reader_status;
	num_readers++;
}

/*
 * Never shrink (implementation limitation).
 * This is O(nb threads). Eventually use a hash table.
 */
static void rcu_remove_reader(pthread_t id)
{
	struct reader_registry *index;

	assert(registry != NULL);
	for (index = registry; index < registry + num_readers; index++) {
		if (pthread_equal(index->tid, id)) {
			memcpy(index, &registry[num_readers - 1],
				sizeof(struct reader_registry));
			registry[num_readers - 1].tid = 0;
			registry[num_readers - 1].urcu_reader_status = NULL;
			num_readers--;
			return;
		}
	}
	/* Hrm not found, forgot to register ? */
	assert(0);
}

void rcu_register_thread(void)
{
	internal_urcu_lock();
	rcu_add_reader(pthread_self());
	internal_urcu_unlock();
	_rcu_thread_online();
}

void rcu_unregister_thread(void)
{
	/*
	 * We have to make the thread offline otherwise we end up dealocking
	 * with a waiting writer.
	 */
	_rcu_thread_offline();
	internal_urcu_lock();
	rcu_remove_reader(pthread_self());
	internal_urcu_unlock();
}
