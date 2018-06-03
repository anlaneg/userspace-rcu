
/*
 * urcu-pointer.c
 *
 * library wrappers to be used by non-LGPL compatible source code.
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

#include <urcu/uatomic.h>

#include "urcu/static/urcu-pointer.h"
/* Do not #define _LGPL_SOURCE to ensure we can emit the wrapper symbols */
#include "urcu-pointer.h"

extern void synchronize_rcu(void);

//获得p指针的一份copy
void *rcu_dereference_sym(void *p)
{
	return _rcu_dereference(p);
}

//实现原子的p=v,且考虑内存berrier
void *rcu_set_pointer_sym(void **p, void *v)
{
	//此操作前，所有的store均已完成
	cmm_wmb();
	uatomic_set(p, v);//原子使*p=v
	return v;
}

//实现p,v变量互换
void *rcu_xchg_pointer_sym(void **p, void *v)
{
	cmm_wmb();
	return uatomic_xchg(p, v);
}

void *rcu_cmpxchg_pointer_sym(void **p, void *old, void *_new)
{
	cmm_wmb();
	return uatomic_cmpxchg(p, old, _new);
}
