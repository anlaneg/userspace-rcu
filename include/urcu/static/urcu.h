#ifndef _URCU_STATIC_H
#define _URCU_STATIC_H

/*
 * urcu-static.h
 *
 * Userspace RCU header.
 *
 * TO BE INCLUDED ONLY IN CODE THAT IS TO BE RECOMPILED ON EACH LIBURCU
 * RELEASE. See urcu.h for linking dynamically with the userspace rcu library.
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

#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include <urcu/config.h>
#include <urcu/compiler.h>
#include <urcu/arch.h>
#include <urcu/system.h>
#include <urcu/uatomic.h>
#include <urcu/list.h>
#include <urcu/futex.h>
#include <urcu/tls-compat.h>
#include <urcu/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default is RCU_MEMBARRIER */
#if !defined(RCU_MEMBARRIER) && !defined(RCU_MB) && !defined(RCU_SIGNAL)
#define RCU_MEMBARRIER
#endif

/*
 * This code section can only be included in LGPL 2.1 compatible source code.
 * See below for the function call wrappers which can be used in code meant to
 * be only linked with the Userspace RCU library. This comes with a small
 * performance degradation on the read-side due to the added function calls.
 * This is required to permit relinking with newer versions of the library.
 */

/*
 * The signal number used by the RCU library can be overridden with
 * -DSIGRCU= when compiling the library.
 * Provide backward compatibility for liburcu 0.3.x SIGURCU.
 */
#ifdef SIGURCU
#define SIGRCU SIGURCU
#endif

#ifndef SIGRCU
#define SIGRCU SIGUSR1
#endif

enum rcu_state {
	RCU_READER_ACTIVE_CURRENT,
	RCU_READER_ACTIVE_OLD,
	RCU_READER_INACTIVE,
};

/*
 * Slave barriers are only guaranteed to be ordered wrt master barriers.
 *
 * The pair ordering is detailed as (O: ordered, X: not ordered) :
 *               slave  master
 *        slave    X      O
 *        master   O      O
 */

#ifdef RCU_MEMBARRIER
#ifdef CONFIG_RCU_FORCE_SYS_MEMBARRIER
#define rcu_has_sys_membarrier_memb	1
#else
extern int rcu_has_sys_membarrier_memb;
#endif

static inline void smp_mb_slave(void)
{
	if (caa_likely(rcu_has_sys_membarrier_memb))
		cmm_barrier();
	else
		cmm_smp_mb();
}
#endif

#ifdef RCU_MB
static inline void smp_mb_slave(void)
{
	cmm_smp_mb();
}
#endif

#ifdef RCU_SIGNAL
static inline void smp_mb_slave(void)
{
	cmm_barrier();
}
#endif

/*
 * The trick here is that RCU_GP_CTR_PHASE must be a multiple of 8 so we can use
 * a full 8-bits, 16-bits or 32-bits bitmask for the lower order bits.
 */
#define RCU_GP_COUNT		(1UL << 0)
/* Use the amount of bits equal to half of the architecture long size */
#define RCU_GP_CTR_PHASE	(1UL << (sizeof(unsigned long) << 2)) //在64位机器上，此值为1<<32
#define RCU_GP_CTR_NEST_MASK (RCU_GP_CTR_PHASE - 1)

struct rcu_gp {
	/*
	 * Global grace period counter.
	 * Contains the current RCU_GP_CTR_PHASE.
	 * Also has a RCU_GP_COUNT of 1, to accelerate the reader fast path.
	 * Written to only by writer with mutex taken.
	 * Read by both writer and readers.
	 */
	unsigned long ctr;

	int32_t futex;
} __attribute__((aligned(CAA_CACHE_LINE_SIZE)));

extern struct rcu_gp rcu_gp;

struct rcu_reader {
	/* Data used by both reader and synchronize_rcu() */
	//通过ctr可以获知各reader的加锁情况，进而知道rcu的grace period
	unsigned long ctr;
	char need_mb;
	/* Data used for registry */
	struct cds_list_head node __attribute__((aligned(CAA_CACHE_LINE_SIZE)));//下面的变量初始化后就纯只读了，这里防cache冲刷这些变量
	pthread_t tid;
	/* Reader registered flag, for internal checks. */
	unsigned int registered:1;//标记是否已注册
};

extern DECLARE_URCU_TLS(struct rcu_reader, rcu_reader);

/*
 * Wake-up waiting synchronize_rcu(). Called from many concurrent threads.
 */
static inline void wake_up_gp(void)
{
	//如果rcu_gp.futex非0，则更新为0，并唤醒等待方
	if (caa_unlikely(uatomic_read(&rcu_gp.futex) == -1)) {
		uatomic_set(&rcu_gp.futex, 0);
		/*
		 * Ignoring return value until we can make this function
		 * return something (because urcu_die() is not publicly
		 * exposed).
		 */
		(void) futex_async(&rcu_gp.futex, FUTEX_WAKE, 1,
				NULL, NULL, 0);
	}
}

static inline enum rcu_state rcu_reader_state(unsigned long *ctr)
{
	unsigned long v;

	/*
	 * Make sure both tests below are done on the same version of *value
	 * to insure consistency.
	 */
	v = CMM_LOAD_SHARED(*ctr);//取ctr的值
	if (!(v	& RCU_GP_CTR_NEST_MASK))
		//未被加锁
		return RCU_READER_INACTIVE;
	if (!((v ^ rcu_gp.ctr) & RCU_GP_CTR_PHASE))
		return RCU_READER_ACTIVE_CURRENT;//加锁了，且加锁时与rcu_gp上的RCU_GP_CTR_PHASE一致，说明自上次变更到现在还没有解锁
	return RCU_READER_ACTIVE_OLD;//加锁了，但自上次变更到现在还没解锁（与当前rcu_gp上的RCU_GP_CTR_PHASE不一致）
}

/*
 * Helper for _rcu_read_lock().  The format of rcu_gp.ctr (as well as
 * the per-thread rcu_reader.ctr) has the upper bits containing a count of
 * _rcu_read_lock() nesting, and a lower-order bit that contains either zero
 * or RCU_GP_CTR_PHASE.  The smp_mb_slave() ensures that the accesses in
 * _rcu_read_lock() happen before the subsequent read-side critical section.
 */
static inline void _rcu_read_lock_update(unsigned long tmp)
{
	if (caa_likely(!(tmp & RCU_GP_CTR_NEST_MASK))) {
		//当tmp为０时使rcu_reader.ctr等于rcu_gp.ctr
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, _CMM_LOAD_SHARED(rcu_gp.ctr));
		smp_mb_slave();//确保写不乱序
	} else
		//设置URCU_TLS(rcu_reader).ctr　= tmp + RCU_GP_COUNT（１）
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, tmp + RCU_GP_COUNT);
}

/*
 * Enter an RCU read-side critical section.
 *
 * The first cmm_barrier() call ensures that the compiler does not reorder
 * the body of _rcu_read_lock() with a mutex.
 *
 * This function and its helper are both less than 10 lines long.  The
 * intent is that this function meets the 10-line criterion in LGPL,
 * allowing this function to be invoked directly from non-LGPL code.
 */
static inline void _rcu_read_lock(void)
{
	unsigned long tmp;

	//断言当前线程已注册
	urcu_assert(URCU_TLS(rcu_reader).registered);
	//要求编译器单独优化其上下的代码
	cmm_barrier();
	//取ctr副本，并校验未打上RCU_GP_CTR_NEST_MASK标记
	tmp = URCU_TLS(rcu_reader).ctr;
	//不容许nest过多层
	urcu_assert((tmp & RCU_GP_CTR_NEST_MASK) != RCU_GP_CTR_NEST_MASK);
	//如果tmp为０，则使ctr＝rcu_gp.ctr,否则ctr在tmp的基础上自增１
	_rcu_read_lock_update(tmp);
}

/*
 * This is a helper function for _rcu_read_unlock().
 *
 * The first smp_mb_slave() call ensures that the critical section is
 * seen to precede the store to rcu_reader.ctr.
 * The second smp_mb_slave() call ensures that we write to rcu_reader.ctr
 * before reading the update-side futex.
 */
static inline void _rcu_read_unlock_update_and_wakeup(unsigned long tmp)
{
	if (caa_likely((tmp & RCU_GP_CTR_NEST_MASK) == RCU_GP_COUNT)) {
		//未nest的解锁，通过减去RCU_GP_COUNT使其归于０
		smp_mb_slave();
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, tmp - RCU_GP_COUNT);
		smp_mb_slave();
		//唤醒等待的更新者
		wake_up_gp();
	} else
		//存在nest的解锁，仅使其减１
		_CMM_STORE_SHARED(URCU_TLS(rcu_reader).ctr, tmp - RCU_GP_COUNT);
}

/*
 * Exit an RCU read-side crtical section.  Both this function and its
 * helper are smaller than 10 lines of code, and are intended to be
 * usable by non-LGPL code, as called out in LGPL.
 */
static inline void _rcu_read_unlock(void)
{
	unsigned long tmp;

	//断言线程已注册
	urcu_assert(URCU_TLS(rcu_reader).registered);
	//取本线程ctr
	tmp = URCU_TLS(rcu_reader).ctr;
	//断言tmp一定不为０（如果等于０，则存在未加锁即解锁的情况）
	urcu_assert(tmp & RCU_GP_CTR_NEST_MASK);
	_rcu_read_unlock_update_and_wakeup(tmp);
	cmm_barrier();	/* Ensure the compiler does not reorder us with mutex */
}

/*
 * Returns whether within a RCU read-side critical section.
 *
 * This function is less than 10 lines long.  The intent is that this
 * function meets the 10-line criterion for LGPL, allowing this function
 * to be invoked directly from non-LGPL code.
 */
static inline int _rcu_read_ongoing(void)
{
	return URCU_TLS(rcu_reader).ctr & RCU_GP_CTR_NEST_MASK;
}

#ifdef __cplusplus
}
#endif

#endif /* _URCU_STATIC_H */
