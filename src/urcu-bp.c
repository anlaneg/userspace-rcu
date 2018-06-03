/*
 * urcu-bp.c
 *
 * Userspace RCU library, "bulletproof" version.
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "urcu/arch.h"
#include "urcu/wfcqueue.h"
#include "urcu/map/urcu-bp.h"
#include "urcu/static/urcu-bp.h"
#include "urcu-pointer.h"
#include "urcu/tls-compat.h"

#include "urcu-die.h"

/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
//urcu-bp.h在包含时不会传_LGPL_SOURCE
#undef _LGPL_SOURCE
#include "urcu-bp.h"
#define _LGPL_SOURCE

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifdef __linux__
static
void *mremap_wrapper(void *old_address, size_t old_size,
		size_t new_size, int flags)
{
	//remap旧的地址old_address
	return mremap(old_address, old_size, new_size, flags);
}
#else

#define MREMAP_MAYMOVE	1
#define MREMAP_FIXED	2

/*
 * mremap wrapper for non-Linux systems not allowing MAYMOVE.
 * This is not generic.
*/
static
void *mremap_wrapper(void *old_address, size_t old_size,
		size_t new_size, int flags)
{
	assert(!(flags & MREMAP_MAYMOVE));

	return MAP_FAILED;
}
#endif

/* Sleep delay in ms */
#define RCU_SLEEP_DELAY_MS	10
#define INIT_NR_THREADS		8
#define ARENA_INIT_ALLOC		\
	sizeof(struct registry_chunk)	\
	+ INIT_NR_THREADS * sizeof(struct rcu_reader)

/*
 * Active attempts to check for reader Q.S. before calling sleep().
 */
#define RCU_QS_ACTIVE_ATTEMPTS 100

static
int rcu_bp_refcount;

/* If the headers do not support membarrier system call, fall back smp_mb. */
#ifdef __NR_membarrier
# define membarrier(...)		syscall(__NR_membarrier, __VA_ARGS__)
#else
# define membarrier(...)		-ENOSYS
#endif

enum membarrier_cmd {
	MEMBARRIER_CMD_QUERY				= 0,
	MEMBARRIER_CMD_SHARED				= (1 << 0),
	/* reserved for MEMBARRIER_CMD_SHARED_EXPEDITED (1 << 1) */
	/* reserved for MEMBARRIER_CMD_PRIVATE (1 << 2) */
	MEMBARRIER_CMD_PRIVATE_EXPEDITED		= (1 << 3),
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED	= (1 << 4),
};

static
void __attribute__((constructor)) rcu_bp_init(void);
static
void __attribute__((destructor)) rcu_bp_exit(void);

#ifndef CONFIG_RCU_FORCE_SYS_MEMBARRIER
int urcu_bp_has_sys_membarrier;
#endif

/*
 * rcu_gp_lock ensures mutual exclusion between threads calling
 * synchronize_rcu().
 */
static pthread_mutex_t rcu_gp_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * rcu_registry_lock ensures mutual exclusion between threads
 * registering and unregistering themselves to/from the registry, and
 * with threads reading that registry from synchronize_rcu(). However,
 * this lock is not held all the way through the completion of awaiting
 * for the grace period. It is sporadically released between iterations
 * on the registry.
 * rcu_registry_lock may nest inside rcu_gp_lock.
 */
//用来保护在线程的注册，解注册，读线程情况，使这三种情况互斥
static pthread_mutex_t rcu_registry_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
static int initialized;

static pthread_key_t urcu_bp_key;

struct rcu_gp rcu_gp = { .ctr = RCU_GP_COUNT };

/*
 * Pointer to registry elements. Written to only by each individual reader. Read
 * by both the reader and the writers.
 */
DEFINE_URCU_TLS(struct rcu_reader *, rcu_reader);

static CDS_LIST_HEAD(registry);

struct registry_chunk {
	size_t data_len;		/* data length */
	size_t used;			/* amount of data used */
	struct cds_list_head node;	/* chunk_list node */
	char data[];
};

struct registry_arena {
	struct cds_list_head chunk_list;
};

static struct registry_arena registry_arena = {
	.chunk_list = CDS_LIST_HEAD_INIT(registry_arena.chunk_list),
};

/* Saved fork signal mask, protected by rcu_gp_lock */
static sigset_t saved_fork_signal_mask;

//实现pthread_mutex加锁
static void mutex_lock(pthread_mutex_t *mutex)
{
	int ret;

#ifndef DISTRUST_SIGNALS_EXTREME
	ret = pthread_mutex_lock(mutex);
	if (ret)
		urcu_die(ret);
#else /* #ifndef DISTRUST_SIGNALS_EXTREME */
	//调用trylock实现加锁尝试
	while ((ret = pthread_mutex_trylock(mutex)) != 0) {
		if (ret != EBUSY && ret != EINTR)
			urcu_die(ret);
		poll(NULL,0,10);
	}
#endif /* #else #ifndef DISTRUST_SIGNALS_EXTREME */
}

//实现mutex解锁
static void mutex_unlock(pthread_mutex_t *mutex)
{
	int ret;

	ret = pthread_mutex_unlock(mutex);
	if (ret)
		urcu_die(ret);
}

static void smp_mb_master(void)
{
	if (caa_likely(urcu_bp_has_sys_membarrier)) {
		if (membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0))
			urcu_die(errno);
	} else {
		cmm_smp_mb();
	}
}

/*
 * Always called with rcu_registry lock held. Releases this lock between
 * iterations and grabs it again. Holds the lock when it returns.
 */
//等待input_readers中的元素，使其可划分到cur_snap_readers,qsreaders队列中
static void wait_for_readers(struct cds_list_head *input_readers,
			struct cds_list_head *cur_snap_readers,
			struct cds_list_head *qsreaders)
{
	unsigned int wait_loops = 0;
	struct rcu_reader *index, *tmp;

	/*
	 * Wait for each thread URCU_TLS(rcu_reader).ctr to either
	 * indicate quiescence (not nested), or observe the current
	 * rcu_gp.ctr value.
	 */
	for (;;) {
		if (wait_loops < RCU_QS_ACTIVE_ATTEMPTS)
			wait_loops++;

		cds_list_for_each_entry_safe(index, tmp, input_readers, node) {
			switch (rcu_reader_state(&index->ctr)) {
			case RCU_READER_ACTIVE_CURRENT://在当前区间有加锁，需要等待其解锁
				if (cur_snap_readers) {
					//将此元素移至cur_snap_readers链上
					cds_list_move(&index->node,
						cur_snap_readers);
					break;
				}
				/* Fall-through */
			case RCU_READER_INACTIVE://在当前区间内无加锁（只是在检测期没有加锁，可能现在加锁了，故不可排除）
				//将此元素移至qsreaders链上
				cds_list_move(&index->node, qsreaders);
				break;
			case RCU_READER_ACTIVE_OLD://在当前区之前加锁
				/*
				 * Old snapshot. Leaving node in
				 * input_readers will make us busy-loop
				 * until the snapshot becomes current or
				 * the reader becomes inactive.
				 */
				break;
			}
		}

		if (cds_list_empty(input_readers)) {
			//均在cur_snap_readers或者qsreaders链上
			break;
		} else {
			//临时解开registry_lock，使其可注册，解注册线程
			/* Temporarily unlock the registry lock. */
			mutex_unlock(&rcu_registry_lock);
			if (wait_loops >= RCU_QS_ACTIVE_ATTEMPTS)
				(void) poll(NULL, 0, RCU_SLEEP_DELAY_MS);
			else
				caa_cpu_relax();
			/* Re-lock the registry lock before the next loop. */
			mutex_lock(&rcu_registry_lock);
		}
	}
}

//本函数退出时，可保证所有读者均已完成锁的释放，延迟时间到。
void synchronize_rcu(void)
{
	CDS_LIST_HEAD(cur_snap_readers);
	CDS_LIST_HEAD(qsreaders);
	sigset_t newmask, oldmask;
	int ret;

	//阻塞所有信号
	ret = sigfillset(&newmask);
	assert(!ret);
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	assert(!ret);

	mutex_lock(&rcu_gp_lock);

	mutex_lock(&rcu_registry_lock);

	//无注册的线程，直接退出
	if (cds_list_empty(&registry))
		goto out;

	/* All threads should read qparity before accessing data structure
	 * where new ptr points to. */
	/* Write new ptr before changing the qparity */
	smp_mb_master();

	/*
	 * Wait for readers to observe original parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	//将register划分为三类 1.registry 在上个周期加锁的
	//				     2.cur_snap_reader 在检测时本周期加锁的
	//                   3.qsreaders 在检测时本周期未加锁的，可能在检测后加锁，也可能没
	//此函数退出时，要求registry为空，即保证不再存在上个周期加锁还未解锁的情况
	wait_for_readers(&registry, &cur_snap_readers, &qsreaders);

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/* Switch parity: 0 -> 1, 1 -> 0 */
	//变更周期，为ctr加上标记（或者清楚上原有的标记）
	CMM_STORE_SHARED(rcu_gp.ctr, rcu_gp.ctr ^ RCU_GP_CTR_PHASE);

	/*
	 * Must commit qparity update to memory before waiting for other parity
	 * quiescent state. Failure to do so could result in the writer waiting
	 * forever while new readers are always accessing data (no progress).
	 * Ensured by CMM_STORE_SHARED and CMM_LOAD_SHARED.
	 */

	/*
	 * Adding a cmm_smp_mb() which is _not_ formally required, but makes the
	 * model easier to understand. It does not have a big performance impact
	 * anyway, given this is the write-side.
	 */
	cmm_smp_mb();

	/*
	 * Wait for readers to observe new parity or be quiescent.
	 * wait_for_readers() can release and grab again rcu_registry_lock
	 * interally.
	 */
	//将cur_snap_readers划分为二类 1.cur_snap_reader 上次检测时，在上个周期加锁的
	//                           2.在检测时本周期未加锁的，(可能在检测后加锁，也可能没);在本检测周期加锁的
	//此函数退出时，要求cur_snap_reader为空，即保证不再存在上个周期加锁还未解锁的情况,
	wait_for_readers(&cur_snap_readers, NULL, &qsreaders);

	/*
	 * Put quiescent reader list back into registry.
	 */
	//还原registry
	cds_list_splice(&qsreaders, &registry);

	/*
	 * Finish waiting for reader threads before letting the old ptr being
	 * freed.
	 */
	smp_mb_master();
out:
	mutex_unlock(&rcu_registry_lock);
	mutex_unlock(&rcu_gp_lock);
	//还原信号
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

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

//返回此线程加锁情况
int rcu_read_ongoing(void)
{
	return _rcu_read_ongoing();
}

/*
 * Only grow for now. If empty, allocate a ARENA_INIT_ALLOC sized chunk.
 * Else, try expanding the last chunk. If this fails, allocate a new
 * chunk twice as big as the last chunk.
 * Memory used by chunks _never_ moves. A chunk could theoretically be
 * freed when all "used" slots are released, but we don't do it at this
 * point.
 */
static
void expand_arena(struct registry_arena *arena)
{
	struct registry_chunk *new_chunk, *last_chunk;
	size_t old_chunk_len, new_chunk_len;

	/* No chunk. */
	if (cds_list_empty(&arena->chunk_list)) {
		//chunk_list为空，需要申请并加入节点
		assert(ARENA_INIT_ALLOC >=
			sizeof(struct registry_chunk)
			+ sizeof(struct rcu_reader));
		//申请空间
		new_chunk_len = ARENA_INIT_ALLOC;
		new_chunk = (struct registry_chunk *) mmap(NULL,
			new_chunk_len,
			PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE,
			-1, 0);
		if (new_chunk == MAP_FAILED)
			abort();//申请失败
		//初始化后加入到arena->chunk_list中
		memset(new_chunk, 0, new_chunk_len);
		new_chunk->data_len =
			new_chunk_len - sizeof(struct registry_chunk);
		cds_list_add_tail(&new_chunk->node, &arena->chunk_list);
		return;		/* We're done. */
	}

	/* Try expanding last chunk. */
	last_chunk = cds_list_entry(arena->chunk_list.prev,
		struct registry_chunk, node);
	old_chunk_len =
		last_chunk->data_len + sizeof(struct registry_chunk);
	new_chunk_len = old_chunk_len << 1;

	/* Don't allow memory mapping to move, just expand. */
	//采用remap扩大原来申请的空间
	new_chunk = mremap_wrapper(last_chunk, old_chunk_len,
		new_chunk_len, 0);
	if (new_chunk != MAP_FAILED) {
		//申请成功，初始化多余部分
		/* Should not have moved. */
		assert(new_chunk == last_chunk);
		memset((char *) last_chunk + old_chunk_len, 0,
			new_chunk_len - old_chunk_len);
		last_chunk->data_len =
			new_chunk_len - sizeof(struct registry_chunk);
		return;		/* We're done. */
	}

	/* Remap did not succeed, we need to add a new chunk. */
	//remap不成功，采用mmap申请一会新空间，并进行挂接
	new_chunk = (struct registry_chunk *) mmap(NULL,
		new_chunk_len,
		PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1, 0);
	if (new_chunk == MAP_FAILED)
		//申请失败，报错
		abort();
	memset(new_chunk, 0, new_chunk_len);
	new_chunk->data_len =
		new_chunk_len - sizeof(struct registry_chunk);
	cds_list_add_tail(&new_chunk->node, &arena->chunk_list);
}

//管理内存申请
static
struct rcu_reader *arena_alloc(struct registry_arena *arena)
{
	struct registry_chunk *chunk;
	struct rcu_reader *rcu_reader_reg;
	int expand_done = 0;	/* Only allow to expand once per alloc */
	size_t len = sizeof(struct rcu_reader);

retry:
	cds_list_for_each_entry(chunk, &arena->chunk_list, node) {
		if (chunk->data_len - chunk->used < len)
			continue;
		/* Find spot */
		//找一个空闲的点
		for (rcu_reader_reg = (struct rcu_reader *) &chunk->data[0];
				rcu_reader_reg < (struct rcu_reader *) &chunk->data[chunk->data_len];
				rcu_reader_reg++) {
			if (!rcu_reader_reg->alloc) {
				rcu_reader_reg->alloc = 1;
				chunk->used += len;
				return rcu_reader_reg;
			}
		}
	}

	//没有查找，且需要扩展，则进行扩展
	if (!expand_done) {
		expand_arena(arena);
		expand_done = 1;
		goto retry;
	}

	return NULL;
}

/* Called with signals off and mutex locked */
static
void add_thread(void)
{
	struct rcu_reader *rcu_reader_reg;
	int ret;

	//申请一个rcu_reader_reg空间
	rcu_reader_reg = arena_alloc(&registry_arena);
	if (!rcu_reader_reg)
		abort();
	//指定为私有数据
	ret = pthread_setspecific(urcu_bp_key, rcu_reader_reg);
	if (ret)
		abort();

	/* Add to registry */
	//完成线程注册
	rcu_reader_reg->tid = pthread_self();
	assert(rcu_reader_reg->ctr == 0);
	cds_list_add(&rcu_reader_reg->node, &registry);
	/*
	 * Reader threads are pointing to the reader registry. This is
	 * why its memory should never be relocated.
	 */
	//将私有变量存入tls中，以消除函数访问问题
	URCU_TLS(rcu_reader) = rcu_reader_reg;
}

/* Called with mutex locked */
static
void cleanup_thread(struct registry_chunk *chunk,
		struct rcu_reader *rcu_reader_reg)
{
	rcu_reader_reg->ctr = 0;
	cds_list_del(&rcu_reader_reg->node);
	rcu_reader_reg->tid = 0;
	rcu_reader_reg->alloc = 0;
	chunk->used -= sizeof(struct rcu_reader);
}

static
struct registry_chunk *find_chunk(struct rcu_reader *rcu_reader_reg)
{
	struct registry_chunk *chunk;

	cds_list_for_each_entry(chunk, &registry_arena.chunk_list, node) {
		if (rcu_reader_reg < (struct rcu_reader *) &chunk->data[0])
			continue;
		if (rcu_reader_reg >= (struct rcu_reader *) &chunk->data[chunk->data_len])
			continue;
		return chunk;
	}
	return NULL;
}

/* Called with signals off and mutex locked */
static
void remove_thread(struct rcu_reader *rcu_reader_reg)
{
	cleanup_thread(find_chunk(rcu_reader_reg), rcu_reader_reg);
	URCU_TLS(rcu_reader) = NULL;
}

/* Disable signals, take mutex, add to registry */
//实现rcu线程注册
void rcu_bp_register(void)
{
	sigset_t newmask, oldmask;
	int ret;

	//阻塞所有信号
	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();

	/*
	 * Check if a signal concurrently registered our thread since
	 * the check in rcu_read_lock().
	 */
	if (URCU_TLS(rcu_reader))
		goto end;

	/*
	 * Take care of early registration before urcu_bp constructor.
	 */
	rcu_bp_init();

	//添加进线程
	mutex_lock(&rcu_registry_lock);
	add_thread();
	mutex_unlock(&rcu_registry_lock);
	//恢复信号
end:
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
}

/* Disable signals, take mutex, remove from registry */
//解除线程注册
static
void rcu_bp_unregister(struct rcu_reader *rcu_reader_reg)
{
	sigset_t newmask, oldmask;
	int ret;

	ret = sigfillset(&newmask);
	if (ret)
		abort();
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	if (ret)
		abort();

	mutex_lock(&rcu_registry_lock);
	remove_thread(rcu_reader_reg);
	mutex_unlock(&rcu_registry_lock);
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	if (ret)
		abort();
	rcu_bp_exit();
}

/*
 * Remove thread from the registry when it exits, and flag it as
 * destroyed so garbage collection can take care of it.
 */
static
void urcu_bp_thread_exit_notifier(void *rcu_key)
{
	//保证线程退出时解注册
	rcu_bp_unregister(rcu_key);
}

#ifdef CONFIG_RCU_FORCE_SYS_MEMBARRIER
static
void rcu_sys_membarrier_status(bool available)
{
	if (!available)
		abort();
}
#else
static
void rcu_sys_membarrier_status(bool available)
{
	if (!available)
		return;
	urcu_bp_has_sys_membarrier = 1;
}
#endif

static
void rcu_sys_membarrier_init(void)
{
	bool available = false;
	int mask;

	mask = membarrier(MEMBARRIER_CMD_QUERY, 0);
	if (mask >= 0) {
		if (mask & MEMBARRIER_CMD_PRIVATE_EXPEDITED) {
			if (membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0))
				urcu_die(errno);
			available = true;
		}
	}
	rcu_sys_membarrier_status(available);
}

//bp方式初始化，创建私有key
static
void rcu_bp_init(void)
{
	mutex_lock(&init_lock);
	if (!rcu_bp_refcount++) {
		int ret;

		//注册线程退出时处理
		ret = pthread_key_create(&urcu_bp_key,
				urcu_bp_thread_exit_notifier);
		if (ret)
			abort();
		rcu_sys_membarrier_init();
		initialized = 1;
	}
	mutex_unlock(&init_lock);
}

//bp方式退出
static
void rcu_bp_exit(void)
{
	mutex_lock(&init_lock);
	if (!--rcu_bp_refcount) {
		struct registry_chunk *chunk, *tmp;
		int ret;

		cds_list_for_each_entry_safe(chunk, tmp,
				&registry_arena.chunk_list, node) {
			munmap((void *) chunk, chunk->data_len
					+ sizeof(struct registry_chunk));
		}
		CDS_INIT_LIST_HEAD(&registry_arena.chunk_list);
		ret = pthread_key_delete(urcu_bp_key);
		if (ret)
			abort();
	}
	mutex_unlock(&init_lock);
}

/*
 * Holding the rcu_gp_lock and rcu_registry_lock across fork will make
 * sure we fork() don't race with a concurrent thread executing with
 * any of those locks held. This ensures that the registry and data
 * protected by rcu_gp_lock are in a coherent state in the child.
 */
void rcu_bp_before_fork(void)
{
	sigset_t newmask, oldmask;
	int ret;

	//阻塞所有信号
	ret = sigfillset(&newmask);
	assert(!ret);
	ret = pthread_sigmask(SIG_BLOCK, &newmask, &oldmask);
	assert(!ret);
	mutex_lock(&rcu_gp_lock);//禁止调用rcu同步函数
	mutex_lock(&rcu_registry_lock);//禁止注册线程
	saved_fork_signal_mask = oldmask;//记录旧的信号mask
}

void rcu_bp_after_fork_parent(void)
{
	sigset_t oldmask;
	int ret;

	oldmask = saved_fork_signal_mask;
	mutex_unlock(&rcu_registry_lock);//容许线程注册
	mutex_unlock(&rcu_gp_lock);//容许rcu调用
	//还原信号
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

/*
 * Prune all entries from registry except our own thread. Fits the Linux
 * fork behavior. Called with rcu_gp_lock and rcu_registry_lock held.
 */
static
void urcu_bp_prune_registry(void)
{
	struct registry_chunk *chunk;
	struct rcu_reader *rcu_reader_reg;

	cds_list_for_each_entry(chunk, &registry_arena.chunk_list, node) {
		for (rcu_reader_reg = (struct rcu_reader *) &chunk->data[0];
				rcu_reader_reg < (struct rcu_reader *) &chunk->data[chunk->data_len];
				rcu_reader_reg++) {
			if (!rcu_reader_reg->alloc)
				continue;
			if (rcu_reader_reg->tid == pthread_self())
				continue;
			cleanup_thread(chunk, rcu_reader_reg);
		}
	}
}

//fork后子进程调用
void rcu_bp_after_fork_child(void)
{
	sigset_t oldmask;
	int ret;

	urcu_bp_prune_registry();
	oldmask = saved_fork_signal_mask;
	mutex_unlock(&rcu_registry_lock);//容许新线程注册
	mutex_unlock(&rcu_gp_lock);//容许rcu同步
	//还原信号注册
	ret = pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	assert(!ret);
}

//实现p指针的一份copy
void *rcu_dereference_sym_bp(void *p)
{
	return _rcu_dereference(p);
}

//实现原子set
void *rcu_set_pointer_sym_bp(void **p, void *v)
{
	cmm_wmb();
	uatomic_set(p, v);
	return v;
}

//实现原子交换
void *rcu_xchg_pointer_sym_bp(void **p, void *v)
{
	cmm_wmb();
	return uatomic_xchg(p, v);
}

//实现原子的比对并赋值
void *rcu_cmpxchg_pointer_sym_bp(void **p, void *old, void *_new)
{
	cmm_wmb();
	return uatomic_cmpxchg(p, old, _new);
}

//申明rcu flavor
DEFINE_RCU_FLAVOR(rcu_flavor);

#include "urcu-call-rcu-impl.h"
#include "urcu-defer-impl.h"
