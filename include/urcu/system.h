#ifndef _URCU_SYSTEM_H
#define _URCU_SYSTEM_H

/*
 * system.h
 *
 * System definitions.
 *
 * Copyright (c) 2009 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#include <urcu/compiler.h>
#include <urcu/arch.h>

/*
 * Identify a shared load. A cmm_smp_rmc() or cmm_smp_mc() should come
 * before the load.
 */
#define _CMM_LOAD_SHARED(p)	       CMM_ACCESS_ONCE(p)

/*
 * Load a data from shared memory, doing a cache flush if required.
 */
#define CMM_LOAD_SHARED(p)			\
	__extension__			\
	({				\
		cmm_smp_rmc();		\
		/*读取p指针，防编译器乱序*/\
		_CMM_LOAD_SHARED(p);	\
	})

/*
 * Identify a shared store. A cmm_smp_wmc() or cmm_smp_mc() should
 * follow the store.
 */
//设置x指针指向的元素为v,防编译器乱序
#define _CMM_STORE_SHARED(x, v)	__extension__ ({ CMM_ACCESS_ONCE(x) = (v); })

/*
 * Store v into x, where x is located in shared memory. Performs the
 * required cache flush after writing. Returns v.
 */
#define CMM_STORE_SHARED(x, v)						\
	__extension__							\
	({								\
		/*设置内存x的值为v*/\
		__typeof__(x) _v = _CMM_STORE_SHARED(x, v);		\
		/*保证x值对其它cpu可见*/\
		cmm_smp_wmc();						\
		_v = _v;	/* Work around clang "unused result" */	\
	})

#endif /* _URCU_SYSTEM_H */
