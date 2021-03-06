/*
 * urcu-call-rcu.c
 *
 * Userspace RCU library - batch memory reclamation with kernel API
 *
 * Copyright (c) 2010 Paul E. McKenney <paulmck@linux.vnet.ibm.com>
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
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <unistd.h>
#include <sched.h>

#include "compat-getcpu.h"
#include "urcu/wfcqueue.h"
#include "urcu-call-rcu.h"
#include "urcu-pointer.h"
#include "urcu/list.h"
#include "urcu/futex.h"
#include "urcu/tls-compat.h"
#include "urcu/ref.h"
#include "urcu-die.h"

#define SET_AFFINITY_CHECK_PERIOD		(1U << 8)	/* 256 */
#define SET_AFFINITY_CHECK_PERIOD_MASK		(SET_AFFINITY_CHECK_PERIOD - 1)

/* Data structure that identifies a call_rcu thread. */

struct call_rcu_data {
	/*
	 * We do not align head on a different cache-line than tail
	 * mainly because call_rcu callback-invocation threads use
	 * batching ("splice") to get an entire list of callbacks, which
	 * effectively empties the queue, and requires to touch the tail
	 * anyway.
	 */
	//指向当前线程上rcu回调队列
	struct cds_wfcq_tail cbs_tail;//尾
	struct cds_wfcq_head cbs_head;//头

	unsigned long flags;
	int32_t futex;//阻塞变量，用于在cbs_head为空时在此变量上阻塞

	//cbs_head队列长度
	unsigned long qlen; /* maintained for debugging. */
	pthread_t tid;//线程id

	int cpu_affinity;//cpu的亲呢性
	unsigned long gp_count;
	struct cds_list_head list;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

struct call_rcu_completion {
	int barrier_count;
	int32_t futex;
	struct urcu_ref ref;
};

struct call_rcu_completion_work {
	struct rcu_head head;
	struct call_rcu_completion *completion;
};

/*
 * List of all call_rcu_data structures to keep valgrind happy.
 * Protected by call_rcu_mutex.
 */

static CDS_LIST_HEAD(call_rcu_data_list);

/* Link a thread using call_rcu() to its call_rcu thread. */
static DEFINE_URCU_TLS(struct call_rcu_data *, thread_call_rcu_data);

/*
 * Guard call_rcu thread creation and atfork handlers.
 */
static pthread_mutex_t call_rcu_mutex = PTHREAD_MUTEX_INITIALIZER;

/* If a given thread does not have its own call_rcu thread, this is default. */

static struct call_rcu_data *default_call_rcu_data;

static struct urcu_atfork *registered_rculfhash_atfork;
static unsigned long registered_rculfhash_atfork_refcount;

/*
 * If the sched_getcpu() and sysconf(_SC_NPROCESSORS_CONF) calls are
 * available, then we can have call_rcu threads assigned to individual
 * CPUs rather than only to specific threads.
 */

#if defined(HAVE_SYSCONF) && (defined(HAVE_SCHED_GETCPU) || defined(HAVE_GETCPUID))

/*
 * Pointer to array of pointers to per-CPU call_rcu_data structures
 * and # CPUs. per_cpu_call_rcu_data is a RCU-protected pointer to an
 * array of RCU-protected pointers to call_rcu_data. call_rcu acts as a
 * RCU read-side and reads per_cpu_call_rcu_data and the per-cpu pointer
 * without mutex. The call_rcu_mutex protects updates.
 */

static struct call_rcu_data **per_cpu_call_rcu_data;
static long maxcpus;

static void maxcpus_reset(void)
{
	maxcpus = 0;
}

/* Allocate the array if it has not already been allocated. */
//通过调用此函数，可使得maxcpu为非0，从而控制创建的线程数(容许创建多个rcu_call线程）
static void alloc_cpu_call_rcu_data(void)
{
	struct call_rcu_data **p;
	static int warned = 0;

	if (maxcpus != 0)
		return;
	maxcpus = sysconf(_SC_NPROCESSORS_CONF);//获取系统cpu数目
	if (maxcpus <= 0) {
		return;
	}
	//为每个cpu申请一个struct call_rcu_data类型
	p = malloc(maxcpus * sizeof(*per_cpu_call_rcu_data));
	if (p != NULL) {
		//清０，并设置
		memset(p, '\0', maxcpus * sizeof(*per_cpu_call_rcu_data));
		rcu_set_pointer(&per_cpu_call_rcu_data, p);
	} else {
		if (!warned) {
			fprintf(stderr, "[error] liburcu: unable to allocate per-CPU pointer array\n");
		}
		warned = 1;
	}
}

#else /* #if defined(HAVE_SYSCONF) && defined(HAVE_SCHED_GETCPU) */

/*
 * per_cpu_call_rcu_data should be constant, but some functions below, used both
 * for cases where cpu number is available and not available, assume it it not
 * constant.
 */
static struct call_rcu_data **per_cpu_call_rcu_data = NULL;
static const long maxcpus = -1;//默认为-1,即只创建一个default rcu线程

static void maxcpus_reset(void)
{
}

static void alloc_cpu_call_rcu_data(void)
{
}

#endif /* #else #if defined(HAVE_SYSCONF) && defined(HAVE_SCHED_GETCPU) */

/* Acquire the specified pthread mutex. */

//封装pthread_mutex_lock函数，实现加锁
static void call_rcu_lock(pthread_mutex_t *pmp)
{
	int ret;

	ret = pthread_mutex_lock(pmp);
	if (ret)
		urcu_die(ret);
}

/* Release the specified pthread mutex. */
//封装pthread_mutex_unlock函数，实现解锁
static void call_rcu_unlock(pthread_mutex_t *pmp)
{
	int ret;

	ret = pthread_mutex_unlock(pmp);
	if (ret)
		urcu_die(ret);
}

/*
 * Periodically retry setting CPU affinity if we migrate.
 * Losing affinity can be caused by CPU hotunplug/hotplug, or by
 * cpuset(7).
 */
#if HAVE_SCHED_SETAFFINITY
static
//设置cpu亲昵性
int set_thread_cpu_affinity(struct call_rcu_data *crdp)
{
	cpu_set_t mask;
	int ret;

	if (crdp->cpu_affinity < 0)
		return 0;//如果cpu亲昵配置为负数，则不生效
	if (++crdp->gp_count & SET_AFFINITY_CHECK_PERIOD_MASK)
		return 0;
	if (urcu_sched_getcpu() == crdp->cpu_affinity)
		return 0;//已设置

	CPU_ZERO(&mask);
	CPU_SET(crdp->cpu_affinity, &mask);
#if SCHED_SETAFFINITY_ARGS == 2
	ret = sched_setaffinity(0, &mask);
#else
	ret = sched_setaffinity(0, sizeof(mask), &mask);//设置cpu亲昵
#endif
	/*
	 * EINVAL is fine: can be caused by hotunplugged CPUs, or by
	 * cpuset(7). This is why we should always retry if we detect
	 * migration.
	 */
	if (ret && errno == EINVAL) {
		ret = 0;
		errno = 0;
	}
	return ret;
}
#else
static
int set_thread_cpu_affinity(struct call_rcu_data *crdp)
{
	return 0;
}
#endif

//等待crdp->futex更改为非-1
static void call_rcu_wait(struct call_rcu_data *crdp)
{
	/* Read call_rcu list before read futex */
	cmm_smp_mb();
	if (uatomic_read(&crdp->futex) != -1)
		return;//变量不为-1,直接返回
	//等待变量变为非-1
	while (futex_async(&crdp->futex, FUTEX_WAIT, -1,
			NULL, NULL, 0)) {
		switch (errno) {
		case EWOULDBLOCK:
			/* Value already changed. */
			return;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. */
		default:
			/* Unexpected error. */
			urcu_die(errno);
		}
	}
}

//知会阻塞在crdp->futex的线程使其不再阻塞
static void call_rcu_wake_up(struct call_rcu_data *crdp)
{
	/* Write to call_rcu list before reading/writing futex */
	cmm_smp_mb();
	if (caa_unlikely(uatomic_read(&crdp->futex) == -1)) {
		uatomic_set(&crdp->futex, 0);
		//知会其它线程本线程已有元素入队,使call_rcu_wait线程返回
		if (futex_async(&crdp->futex, FUTEX_WAKE, 1,
				NULL, NULL, 0) < 0)
			urcu_die(errno);
	}
}

//等待completion->futex更改为非-1
static void call_rcu_completion_wait(struct call_rcu_completion *completion)
{
	/* Read completion barrier count before read futex */
	cmm_smp_mb();
	if (uatomic_read(&completion->futex) != -1)
		return;//如果completion->futex为非-1,则不阻塞，否则阻塞
	while (futex_async(&completion->futex, FUTEX_WAIT, -1,
			NULL, NULL, 0)) {
		switch (errno) {
		case EWOULDBLOCK:
			/* Value already changed. */
			return;
		case EINTR:
			/* Retry if interrupted by signal. */
			break;	/* Get out of switch. */
		default:
			/* Unexpected error. */
			urcu_die(errno);
		}
	}
}

//知会阻塞在completion->futex的线程使其不再阻塞
static void call_rcu_completion_wake_up(struct call_rcu_completion *completion)
{
	/* Write to completion barrier count before reading/writing futex */
	cmm_smp_mb();
	if (caa_unlikely(uatomic_read(&completion->futex) == -1)) {
		uatomic_set(&completion->futex, 0);
		if (futex_async(&completion->futex, FUTEX_WAKE, 1,
				NULL, NULL, 0) < 0)
			urcu_die(errno);
	}
}

/* This is the code run by each call_rcu thread. */

//10ms一个批次，执行rcu回调
static void *call_rcu_thread(void *arg)
{
	unsigned long cbcount;
	struct call_rcu_data *crdp = (struct call_rcu_data *) arg;
	//是否工作线程可real-time此本线程收到响应
	int rt = !!(uatomic_read(&crdp->flags) & URCU_CALL_RCU_RT);

	//设置cpu亲昵
	if (set_thread_cpu_affinity(crdp))
		urcu_die(errno);

	/*
	 * If callbacks take a read-side lock, we need to be registered.
	 */
	//注册rcu线程
	rcu_register_thread();

	URCU_TLS(thread_call_rcu_data) = crdp;//为当前线程设置crdp
	if (!rt) {
		//减少futex，如果在我们重新执行前futex未变化，则我们可以阻塞等待
		uatomic_dec(&crdp->futex);
		/* Decrement futex before reading call_rcu list */
		cmm_smp_mb();
	}
	for (;;) {
		struct cds_wfcq_head cbs_tmp_head;
		struct cds_wfcq_tail cbs_tmp_tail;
		struct cds_wfcq_node *cbs, *cbs_tmp_n;
		enum cds_wfcq_ret splice_ret;

		//设置cpu亲昵性
		if (set_thread_cpu_affinity(crdp))
			urcu_die(errno);

		if (uatomic_read(&crdp->flags) & URCU_CALL_RCU_PAUSE) {
			/*
			 * Pause requested. Become quiescent: remove
			 * ourself from all global lists, and don't
			 * process any callback. The callback lists may
			 * still be non-empty though.
			 */
			rcu_unregister_thread();//解注册
			cmm_smp_mb__before_uatomic_or();//防编译器优化
			uatomic_or(&crdp->flags, URCU_CALL_RCU_PAUSED);//原子or操作，置为paused标记

			//阻塞等待包含RCU_PAUSE标记
			while ((uatomic_read(&crdp->flags) & URCU_CALL_RCU_PAUSE) != 0)
				(void) poll(NULL, 0, 1);
			//清除掉paused标记，重新注册
			uatomic_and(&crdp->flags, ~URCU_CALL_RCU_PAUSED);
			cmm_smp_mb__after_uatomic_and();//防编译器优化
			rcu_register_thread();
		}

		//阻塞交换crdp->cbs_head上的元素到cbs_tmp_head
		cds_wfcq_init(&cbs_tmp_head, &cbs_tmp_tail);
		splice_ret = __cds_wfcq_splice_blocking(&cbs_tmp_head,
			&cbs_tmp_tail, &crdp->cbs_head, &crdp->cbs_tail);
		assert(splice_ret != CDS_WFCQ_RET_WOULDBLOCK);
		assert(splice_ret != CDS_WFCQ_RET_DEST_NON_EMPTY);

		if (splice_ret != CDS_WFCQ_RET_SRC_EMPTY) {
			//等待rcu可执行
			synchronize_rcu();
			cbcount = 0;
			//自crdp->cbs_head上交换到了多个元素，遍历这些元素，并调用对应的回调
			__cds_wfcq_for_each_blocking_safe(&cbs_tmp_head,
					&cbs_tmp_tail, cbs, cbs_tmp_n) {
				struct rcu_head *rhp;
				rhp = caa_container_of(cbs,
					struct rcu_head, next);
				rhp->func(rhp);//调用注册的回调
				cbcount++;
			}
			uatomic_sub(&crdp->qlen, cbcount);//已注册的rcu回调长度清0
		}
		if (uatomic_read(&crdp->flags) & URCU_CALL_RCU_STOP)
			break;//收到线程停止标记，则直接跳出for并退出
		rcu_thread_offline();
		if (!rt) {
			//队列为空，等待唤醒
			if (cds_wfcq_empty(&crdp->cbs_head,
					&crdp->cbs_tail)) {
				call_rcu_wait(crdp);//阻塞等待
				(void) poll(NULL, 0, 10);//延迟10ms
				uatomic_dec(&crdp->futex);//减少futex
				/*
				 * Decrement futex before reading
				 * call_rcu list.
				 */
				cmm_smp_mb();
			} else {
				//刚才队列已处理，但现在已有了，延迟10ms
				(void) poll(NULL, 0, 10);
			}
		} else {
			//总是延迟10ms
			(void) poll(NULL, 0, 10);
		}
		rcu_thread_online();
	}
	if (!rt) {
		/*
		 * Read call_rcu list before write futex.
		 */
		cmm_smp_mb();
		uatomic_set(&crdp->futex, 0);
	}
	uatomic_or(&crdp->flags, URCU_CALL_RCU_STOPPED);//指明线程已停止
	rcu_unregister_thread();//解注册此线程
	return NULL;
}

/*
 * Create both a call_rcu thread and the corresponding call_rcu_data
 * structure, linking the structure in as specified.  Caller must hold
 * call_rcu_mutex.
 */
//初始化crdpp，并创建线程运行call_rcu_thread（此线程负责调起回调）
static void call_rcu_data_init(struct call_rcu_data **crdpp,
			       unsigned long flags,
			       int cpu_affinity)
{
	struct call_rcu_data *crdp;
	int ret;

	crdp = malloc(sizeof(*crdp));
	if (crdp == NULL)
		urcu_die(errno);
	memset(crdp, '\0', sizeof(*crdp));
	cds_wfcq_init(&crdp->cbs_head, &crdp->cbs_tail);
	crdp->qlen = 0;
	crdp->futex = 0;
	crdp->flags = flags;
	cds_list_add(&crdp->list, &call_rcu_data_list);//将crdp添加到call_rcu_data_list中
	crdp->cpu_affinity = cpu_affinity;
	crdp->gp_count = 0;
	cmm_smp_mb();  /* Structure initialized before pointer is planted. *///防下一行先执行
	*crdpp = crdp;
	//构造此crdp对应的线程，实现rcu写回调执行
	ret = pthread_create(&crdp->tid, NULL, call_rcu_thread, crdp);
	if (ret)
		urcu_die(ret);
}

/*
 * Return a pointer to the call_rcu_data structure for the specified
 * CPU, returning NULL if there is none.  We cannot automatically
 * created it because the platform we are running on might not define
 * urcu_sched_getcpu().
 *
 * The call to this function and use of the returned call_rcu_data
 * should be protected by RCU read-side lock.
 */

//返回并创建当前cpu的call_rcu_data，如果不存在，则返回NULL
struct call_rcu_data *get_cpu_call_rcu_data(int cpu)
{
	static int warned = 0;
	struct call_rcu_data **pcpu_crdp;

	pcpu_crdp = rcu_dereference(per_cpu_call_rcu_data);
	if (pcpu_crdp == NULL)
		return NULL;
	if (!warned && maxcpus > 0 && (cpu < 0 || maxcpus <= cpu)) {
		fprintf(stderr, "[error] liburcu: get CPU # out of range\n");
		warned = 1;
	}
	if (cpu < 0 || maxcpus <= cpu)
		return NULL;//参数有误时失回０
	return rcu_dereference(pcpu_crdp[cpu]);
}

/*
 * Return the tid corresponding to the call_rcu thread whose
 * call_rcu_data structure is specified.
 */

pthread_t get_call_rcu_thread(struct call_rcu_data *crdp)
{
	return crdp->tid;
}

/*
 * Create a call_rcu_data structure (with thread) and return a pointer.
 */

static struct call_rcu_data *__create_call_rcu_data(unsigned long flags,
						    int cpu_affinity)
{
	struct call_rcu_data *crdp;

	call_rcu_data_init(&crdp, flags, cpu_affinity);
	return crdp;
}

//创建call_rcu_data,并创建线程处理rcu写回调
struct call_rcu_data *create_call_rcu_data(unsigned long flags,
					   int cpu_affinity)
{
	struct call_rcu_data *crdp;

	call_rcu_lock(&call_rcu_mutex);
	crdp = __create_call_rcu_data(flags, cpu_affinity);
	call_rcu_unlock(&call_rcu_mutex);
	return crdp;
}

/*
 * Set the specified CPU to use the specified call_rcu_data structure.
 *
 * Use NULL to remove a CPU's call_rcu_data structure, but it is
 * the caller's responsibility to dispose of the removed structure.
 * Use get_cpu_call_rcu_data() to obtain a pointer to the old structure
 * (prior to NULLing it out, of course).
 *
 * The caller must wait for a grace-period to pass between return from
 * set_cpu_call_rcu_data() and call to call_rcu_data_free() passing the
 * previous call rcu data as argument.
 */
//指定某一cpu使用crdp
int set_cpu_call_rcu_data(int cpu, struct call_rcu_data *crdp)
{
	static int warned = 0;

	call_rcu_lock(&call_rcu_mutex);
	alloc_cpu_call_rcu_data();
	if (cpu < 0 || maxcpus <= cpu) {
		if (!warned) {
			fprintf(stderr, "[error] liburcu: set CPU # out of range\n");
			warned = 1;
		}
		call_rcu_unlock(&call_rcu_mutex);
		errno = EINVAL;
		return -EINVAL;
	}

	if (per_cpu_call_rcu_data == NULL) {
		call_rcu_unlock(&call_rcu_mutex);
		errno = ENOMEM;
		return -ENOMEM;
	}

	if (per_cpu_call_rcu_data[cpu] != NULL && crdp != NULL) {
		call_rcu_unlock(&call_rcu_mutex);
		errno = EEXIST;
		return -EEXIST;
	}

	rcu_set_pointer(&per_cpu_call_rcu_data[cpu], crdp);
	call_rcu_unlock(&call_rcu_mutex);
	return 0;
}

/*
 * Return a pointer to the default call_rcu_data structure, creating
 * one if need be.  Because we never free call_rcu_data structures,
 * we don't need to be in an RCU read-side critical section.
 */
//获取default_call_rcu_data,如果其对应的线程还没有创建，则创建（不支持cpu亲昵性）
struct call_rcu_data *get_default_call_rcu_data(void)
{
	//已创建，则直接返回
	if (default_call_rcu_data != NULL)
		return rcu_dereference(default_call_rcu_data);
	call_rcu_lock(&call_rcu_mutex);
	//加锁后再查一次
	if (default_call_rcu_data != NULL) {
		call_rcu_unlock(&call_rcu_mutex);
		return default_call_rcu_data;
	}
	//创建default_call_rcu_data,指定cpu亲昵性不设置，flags为0，创建一个rcu回调的执行线程
	call_rcu_data_init(&default_call_rcu_data, 0, -1);
	call_rcu_unlock(&call_rcu_mutex);
	return default_call_rcu_data;
}

/*
 * Return the call_rcu_data structure that applies to the currently
 * running thread.  Any call_rcu_data structure assigned specifically
 * to this thread has first priority, followed by any call_rcu_data
 * structure assigned to the CPU on which the thread is running,
 * followed by the default call_rcu_data structure.  If there is not
 * yet a default call_rcu_data structure, one will be created.
 *
 * Calls to this function and use of the returned call_rcu_data should
 * be protected by RCU read-side lock.
 */
struct call_rcu_data *get_call_rcu_data(void)
{
	struct call_rcu_data *crd;

	//如果有per线程的thread_call_rcu_data，则直接返回
	//此变量在get_default_call_rcu_data()函数下设置
	if (URCU_TLS(thread_call_rcu_data) != NULL)
		return URCU_TLS(thread_call_rcu_data);

	//当maxcpus大于0时，在每个cpu上都有一个rcu的回调函数
	if (maxcpus > 0) {
		crd = get_cpu_call_rcu_data(urcu_sched_getcpu());
		if (crd)
			return crd;
	}

	//由于maxcpu<=0,此时仅支持创建一个rcu_call线程，故创建default_rcu_data
	return get_default_call_rcu_data();
}

/*
 * Return a pointer to this task's call_rcu_data if there is one.
 */

struct call_rcu_data *get_thread_call_rcu_data(void)
{
	return URCU_TLS(thread_call_rcu_data);
}

/*
 * Set this task's call_rcu_data structure as specified, regardless
 * of whether or not this task already had one.  (This allows switching
 * to and from real-time call_rcu threads, for example.)
 *
 * Use NULL to remove a thread's call_rcu_data structure, but it is
 * the caller's responsibility to dispose of the removed structure.
 * Use get_thread_call_rcu_data() to obtain a pointer to the old structure
 * (prior to NULLing it out, of course).
 */

void set_thread_call_rcu_data(struct call_rcu_data *crdp)
{
	URCU_TLS(thread_call_rcu_data) = crdp;
}

/*
 * Create a separate call_rcu thread for each CPU.  This does not
 * replace a pre-existing call_rcu thread -- use the set_cpu_call_rcu_data()
 * function if you want that behavior. Should be paired with
 * free_all_cpu_call_rcu_data() to teardown these call_rcu worker
 * threads.
 * 为每个cpu创建一个单独的call_rcu线程，不会替换忆存在的call_rcu 线程
 */
//调用此函数会导致为每个cpu创建单独的rcu_call线程
int create_all_cpu_call_rcu_data(unsigned long flags)
{
	int i;
	struct call_rcu_data *crdp;
	int ret;

	call_rcu_lock(&call_rcu_mutex);
	//目前此函数有两个版本，一者通过sysconf获取cpu数量，并申请足量的alloc_cpu_call_rcu_data，一者，nothing to do
	alloc_cpu_call_rcu_data();
	call_rcu_unlock(&call_rcu_mutex);
	if (maxcpus <= 0) {
		//maxcpus指系统中cpu数，如果<=0则为参数错误
		errno = EINVAL;
		return -EINVAL;
	}
	if (per_cpu_call_rcu_data == NULL) {
		//alloc_cpu_call_rcu_data申请内存失败
		errno = ENOMEM;
		return -ENOMEM;
	}
	for (i = 0; i < maxcpus; i++) {
		call_rcu_lock(&call_rcu_mutex);
		if (get_cpu_call_rcu_data(i)) {
			//如果此cpu已有对应的rcu_data，则跳过
			call_rcu_unlock(&call_rcu_mutex);
			continue;
		}
		//针对cpu$i创建rcu_data,及执行rcu回调的(创建rcu执行线程）
		crdp = __create_call_rcu_data(flags, i);
		if (crdp == NULL) {
			call_rcu_unlock(&call_rcu_mutex);
			errno = ENOMEM;
			return -ENOMEM;
		}
		call_rcu_unlock(&call_rcu_mutex);
		//设置crdp为cpu$i的rcu_data
		if ((ret = set_cpu_call_rcu_data(i, crdp)) != 0) {
			call_rcu_data_free(crdp);

			/* it has been created by other thread */
			if (ret == -EEXIST)
				continue;

			return ret;
		}
	}
	return 0;
}

/*
 * Wake up the call_rcu thread corresponding to the specified
 * call_rcu_data structure.
 */
//通知rcu线程，已有元素入队，可以开始于活了。
static void wake_call_rcu_thread(struct call_rcu_data *crdp)
{
	if (!(_CMM_LOAD_SHARED(crdp->flags) & URCU_CALL_RCU_RT))
		call_rcu_wake_up(crdp);
}

static void _call_rcu(struct rcu_head *head,
		      void (*func)(struct rcu_head *head),
		      struct call_rcu_data *crdp)
{
	cds_wfcq_node_init(&head->next);//初始化head节点
	head->func = func;//设置回调对应的函数
	//将head加入到crdp队列中
	cds_wfcq_enqueue(&crdp->cbs_head, &crdp->cbs_tail, &head->next);
	uatomic_inc(&crdp->qlen);//增加队列长度
	//知会其它线程自此队列上拿head并处理
	wake_call_rcu_thread(crdp);
}

/*
 * Schedule a function to be invoked after a following grace period.
 * This is the only function that must be called -- the others are
 * only present to allow applications to tune their use of RCU for
 * maximum performance.
 *
 * Note that unless a call_rcu thread has not already been created,
 * the first invocation of call_rcu() will create one.  So, if you
 * need the first invocation of call_rcu() to be fast, make sure
 * to create a call_rcu thread first.  One way to accomplish this is
 * "get_call_rcu_data();", and another is create_all_cpu_call_rcu_data().
 *
 * call_rcu must be called by registered RCU read-side threads.
 */
//注册rcu回调
void call_rcu(struct rcu_head *head,
	      void (*func)(struct rcu_head *head))
{
	struct call_rcu_data *crdp;

	/* Holding rcu read-side lock across use of per-cpu crdp */
	//加读锁
	_rcu_read_lock();
	crdp = get_call_rcu_data();//取私有数据（可引发创建rcu_call执行线程）
	_call_rcu(head, func, crdp);//将回调添加到线程自身的队列中
	//解读锁
	_rcu_read_unlock();
}

/*
 * Free up the specified call_rcu_data structure, terminating the
 * associated call_rcu thread.  The caller must have previously
 * removed the call_rcu_data structure from per-thread or per-CPU
 * usage.  For example, set_cpu_call_rcu_data(cpu, NULL) for per-CPU
 * call_rcu_data structures or set_thread_call_rcu_data(NULL) for
 * per-thread call_rcu_data structures.
 *
 * We silently refuse to free up the default call_rcu_data structure
 * because that is where we put any leftover callbacks.  Note that
 * the possibility of self-spawning callbacks makes it impossible
 * to execute all the callbacks in finite time without putting any
 * newly spawned callbacks somewhere else.  The "somewhere else" of
 * last resort is the default call_rcu_data structure.
 *
 * We also silently refuse to free NULL pointers.  This simplifies
 * the calling code.
 *
 * The caller must wait for a grace-period to pass between return from
 * set_cpu_call_rcu_data() and call to call_rcu_data_free() passing the
 * previous call rcu data as argument.
 *
 * Note: introducing __cds_wfcq_splice_blocking() in this function fixed
 * a list corruption bug in the 0.7.x series. The equivalent fix
 * appeared in 0.6.8 for the stable-0.6 branch.
 */
void call_rcu_data_free(struct call_rcu_data *crdp)
{
	if (crdp == NULL || crdp == default_call_rcu_data) {
		//default_call_rcu_data不能被free
		return;
	}
	if ((uatomic_read(&crdp->flags) & URCU_CALL_RCU_STOPPED) == 0) {
		//如果无stoped标记，则打上stop
		uatomic_or(&crdp->flags, URCU_CALL_RCU_STOP);
		//通知线程干活，使线程退出
		wake_call_rcu_thread(crdp);
		//等待线程退出
		while ((uatomic_read(&crdp->flags) & URCU_CALL_RCU_STOPPED) == 0)
			(void) poll(NULL, 0, 1);
	}
	//退出时可能有一些回调还没有做，将其放在default_call_rcu_data对应的线程上去做
	if (!cds_wfcq_empty(&crdp->cbs_head, &crdp->cbs_tail)) {
		/* Create default call rcu data if need be */
		(void) get_default_call_rcu_data();
		__cds_wfcq_splice_blocking(&default_call_rcu_data->cbs_head,
			&default_call_rcu_data->cbs_tail,
			&crdp->cbs_head, &crdp->cbs_tail);
		uatomic_add(&default_call_rcu_data->qlen,
			    uatomic_read(&crdp->qlen));
		wake_call_rcu_thread(default_call_rcu_data);
	}

	//移除线程对应的crdp,并释放
	call_rcu_lock(&call_rcu_mutex);
	cds_list_del(&crdp->list);
	call_rcu_unlock(&call_rcu_mutex);

	free(crdp);
}

/*
 * Clean up all the per-CPU call_rcu threads.
 */
void free_all_cpu_call_rcu_data(void)
{
	int cpu;
	struct call_rcu_data **crdp;
	static int warned = 0;

	if (maxcpus <= 0)
		return;

	crdp = malloc(sizeof(*crdp) * maxcpus);
	if (!crdp) {
		if (!warned) {
			fprintf(stderr, "[error] liburcu: unable to allocate per-CPU pointer array\n");
		}
		warned = 1;
		return;
	}

	for (cpu = 0; cpu < maxcpus; cpu++) {
		crdp[cpu] = get_cpu_call_rcu_data(cpu);
		if (crdp[cpu] == NULL)
			continue;
		set_cpu_call_rcu_data(cpu, NULL);
	}
	/*
	 * Wait for call_rcu sites acting as RCU readers of the
	 * call_rcu_data to become quiescent.
	 */
	synchronize_rcu();
	for (cpu = 0; cpu < maxcpus; cpu++) {
		if (crdp[cpu] == NULL)
			continue;
		call_rcu_data_free(crdp[cpu]);
	}
	free(crdp);
}

static
void free_completion(struct urcu_ref *ref)
{
	struct call_rcu_completion *completion;

	completion = caa_container_of(ref, struct call_rcu_completion, ref);
	free(completion);
}

static
void _rcu_barrier_complete(struct rcu_head *head)
{
	struct call_rcu_completion_work *work;
	struct call_rcu_completion *completion;

	work = caa_container_of(head, struct call_rcu_completion_work, head);
	completion = work->completion;
	if (!uatomic_sub_return(&completion->barrier_count, 1))
		//引用减为0时，知会rcu_barrier已完成，通知completion的关注者
		call_rcu_completion_wake_up(completion);
	urcu_ref_put(&completion->ref, free_completion);//减少引用计数
	free(work);
}

/*
 * Wait for all in-flight call_rcu callbacks to complete execution.
 */
//此函数不容许在read-side thread调用,其用于确保所有rcu的callback均已完成执行
void rcu_barrier(void)
{
	struct call_rcu_data *crdp;
	struct call_rcu_completion *completion;
	int count = 0;
	int was_online;

	/* Put in offline state in QSBR. */
	was_online = _rcu_read_ongoing();
	if (was_online)
		rcu_thread_offline();
	/*
	 * Calling a rcu_barrier() within a RCU read-side critical
	 * section is an error.
	 */
	if (_rcu_read_ongoing()) {
		//不容许rcu_barrier在read-side中调用(不保证100%检查出来）
		static int warned = 0;

		if (!warned) {
			fprintf(stderr, "[error] liburcu: rcu_barrier() called from within RCU read-side critical section.\n");
		}
		warned = 1;
		goto online;
	}

	completion = calloc(sizeof(*completion), 1);
	if (!completion)
		urcu_die(errno);

	call_rcu_lock(&call_rcu_mutex);
	//取call_rcu_data_list的长度
	cds_list_for_each_entry(crdp, &call_rcu_data_list, list)
		count++;

	/* Referenced by rcu_barrier() and each call_rcu thread. */
	urcu_ref_set(&completion->ref, count + 1);//增加引用计数
	completion->barrier_count = count;//有多少队列就有多少个count

	//为每个list中插入一个work
	cds_list_for_each_entry(crdp, &call_rcu_data_list, list) {
		struct call_rcu_completion_work *work;

		work = calloc(sizeof(*work), 1);
		if (!work)
			urcu_die(errno);
		work->completion = completion;
		//将此work存入到crdp中，与rcu一起执行，等其执行完成work的阻塞者会收到通知
		_call_rcu(&work->head, _rcu_barrier_complete, crdp);
	}
	call_rcu_unlock(&call_rcu_mutex);

	/* Wait for them */
	//等待completion对应的work被执行
	for (;;) {
		uatomic_dec(&completion->futex);
		/* Decrement futex before reading barrier_count */
		cmm_smp_mb();
		if (!uatomic_read(&completion->barrier_count))
			break;//如果所有crdp均已完成complete的执行，则退出
		//不是所有crdp均已完成，阻塞等待
		call_rcu_completion_wait(completion);
	}

	urcu_ref_put(&completion->ref, free_completion);

online:
	if (was_online)
		rcu_thread_online();
}

/*
 * Acquire the call_rcu_mutex in order to ensure that the child sees
 * all of the call_rcu() data structures in a consistent state. Ensure
 * that all call_rcu threads are in a quiescent state across fork.
 * Suitable for pthread_atfork() and friends.
 */
void call_rcu_before_fork(void)
{
	struct call_rcu_data *crdp;
	struct urcu_atfork *atfork;

	call_rcu_lock(&call_rcu_mutex);

	atfork = registered_rculfhash_atfork;
	if (atfork)
		atfork->before_fork(atfork->priv);

	cds_list_for_each_entry(crdp, &call_rcu_data_list, list) {
		uatomic_or(&crdp->flags, URCU_CALL_RCU_PAUSE);
		cmm_smp_mb__after_uatomic_or();
		wake_call_rcu_thread(crdp);
	}
	cds_list_for_each_entry(crdp, &call_rcu_data_list, list) {
		while ((uatomic_read(&crdp->flags) & URCU_CALL_RCU_PAUSED) == 0)
			(void) poll(NULL, 0, 1);
	}
}

/*
 * Clean up call_rcu data structures in the parent of a successful fork()
 * that is not followed by exec() in the child.  Suitable for
 * pthread_atfork() and friends.
 */
void call_rcu_after_fork_parent(void)
{
	struct call_rcu_data *crdp;
	struct urcu_atfork *atfork;

	cds_list_for_each_entry(crdp, &call_rcu_data_list, list)
		uatomic_and(&crdp->flags, ~URCU_CALL_RCU_PAUSE);
	cds_list_for_each_entry(crdp, &call_rcu_data_list, list) {
		while ((uatomic_read(&crdp->flags) & URCU_CALL_RCU_PAUSED) != 0)
			(void) poll(NULL, 0, 1);
	}
	atfork = registered_rculfhash_atfork;
	if (atfork)
		atfork->after_fork_parent(atfork->priv);
	call_rcu_unlock(&call_rcu_mutex);
}

/*
 * Clean up call_rcu data structures in the child of a successful fork()
 * that is not followed by exec().  Suitable for pthread_atfork() and
 * friends.
 */
void call_rcu_after_fork_child(void)
{
	struct call_rcu_data *crdp, *next;
	struct urcu_atfork *atfork;

	/* Release the mutex. */
	call_rcu_unlock(&call_rcu_mutex);

	atfork = registered_rculfhash_atfork;
	if (atfork)
		atfork->after_fork_child(atfork->priv);

	/* Do nothing when call_rcu() has not been used */
	if (cds_list_empty(&call_rcu_data_list))
		return;

	/*
	 * Allocate a new default call_rcu_data structure in order
	 * to get a working call_rcu thread to go with it.
	 */
	default_call_rcu_data = NULL;
	(void)get_default_call_rcu_data();

	/* Cleanup call_rcu_data pointers before use */
	maxcpus_reset();
	free(per_cpu_call_rcu_data);
	rcu_set_pointer(&per_cpu_call_rcu_data, NULL);
	URCU_TLS(thread_call_rcu_data) = NULL;

	/*
	 * Dispose of all of the rest of the call_rcu_data structures.
	 * Leftover call_rcu callbacks will be merged into the new
	 * default call_rcu thread queue.
	 */
	cds_list_for_each_entry_safe(crdp, next, &call_rcu_data_list, list) {
		if (crdp == default_call_rcu_data)
			continue;
		uatomic_set(&crdp->flags, URCU_CALL_RCU_STOPPED);
		call_rcu_data_free(crdp);
	}
}

void urcu_register_rculfhash_atfork(struct urcu_atfork *atfork)
{
	call_rcu_lock(&call_rcu_mutex);
	if (registered_rculfhash_atfork_refcount++)
		goto end;
	registered_rculfhash_atfork = atfork;
end:
	call_rcu_unlock(&call_rcu_mutex);
}

void urcu_unregister_rculfhash_atfork(struct urcu_atfork *atfork)
{
	call_rcu_lock(&call_rcu_mutex);
	if (--registered_rculfhash_atfork_refcount)
		goto end;
	registered_rculfhash_atfork = NULL;
end:
	call_rcu_unlock(&call_rcu_mutex);
}
