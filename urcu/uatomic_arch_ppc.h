#ifndef _URCU_ARCH_UATOMIC_PPC_H
#define _URCU_ARCH_UATOMIC_PPC_H

/* 
 * Copyright (c) 1991-1994 by Xerox Corporation.  All rights reserved.
 * Copyright (c) 1996-1999 by Silicon Graphics.  All rights reserved.
 * Copyright (c) 1999-2004 Hewlett-Packard Development Company, L.P.
 * Copyright (c) 2009      Mathieu Desnoyers
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 *
 * Code inspired from libuatomic_ops-1.2, inherited in part from the
 * Boehm-Demers-Weiser conservative garbage collector.
 */

#include <urcu/compiler.h>
#include <urcu/system.h>

#ifndef __SIZEOF_LONG__
#ifdef __powerpc64__
#define __SIZEOF_LONG__ 8
#else
#define __SIZEOF_LONG__ 4
#endif
#endif

#ifndef BITS_PER_LONG
#define BITS_PER_LONG	(__SIZEOF_LONG__ * 8)
#endif

#define ILLEGAL_INSTR	".long	0xd00d00"

#define uatomic_set(addr, v)	STORE_SHARED(*(addr), (v))
#define uatomic_read(addr)	LOAD_SHARED(*(addr))

/*
 * Using a isync as second barrier for exchange to provide acquire semantic.
 * According to uatomic_ops/sysdeps/gcc/powerpc.h, the documentation is "fairly
 * explicit that this also has acquire semantics."
 * Derived from AO_compare_and_swap(), but removed the comparison.
 */

/* xchg */

static inline __attribute__((always_inline))
unsigned long _uatomic_exchange(void *addr, unsigned long val, int len)
{
	switch (len) {
	case 4:
	{
		unsigned int result;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"lwarx %0,0,%1\n"	/* load and reserve */
			"stwcx. %2,0,%1\n"	/* else store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
				: "=&r"(result)
				: "r"(addr), "r"(val)
				: "memory", "cc");

		return result;
	}
#if (BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long result;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"ldarx %0,0,%1\n"	/* load and reserve */
			"stdcx. %2,0,%1\n"	/* else store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
				: "=&r"(result)
				: "r"(addr), "r"(val)
				: "memory", "cc");

		return result;
	}
#endif
	}
	/* generate an illegal instruction. Cannot catch this with linker tricks
	 * when optimizations are disabled. */
	__asm__ __volatile__(ILLEGAL_INSTR);
	return 0;
}

#define uatomic_xchg(addr, v)						    \
	((__typeof__(*(addr))) _uatomic_exchange((addr), (unsigned long)(v), \
						sizeof(*(addr))))
/* cmpxchg */

static inline __attribute__((always_inline))
unsigned long _uatomic_cmpxchg(void *addr, unsigned long old,
			      unsigned long _new, int len)
{
	switch (len) {
	case 4:
	{
		unsigned int old_val;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"lwarx %0,0,%1\n"	/* load and reserve */
			"cmpd %0,%3\n"		/* if load is not equal to */
			"bne 2f\n"		/* old, fail */
			"stwcx. %2,0,%1\n"	/* else store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
		"2:\n"
				: "=&r"(old_val)
				: "r"(addr), "r"((unsigned int)_new),
				  "r"((unsigned int)old)
				: "memory", "cc");

		return old_val;
	}
#if (BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long old_val;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"ldarx %0,0,%1\n"	/* load and reserve */
			"cmpd %0,%3\n"		/* if load is not equal to */
			"bne 2f\n"		/* old, fail */
			"stdcx. %2,0,%1\n"	/* else store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
		"2:\n"
				: "=&r"(old_val),
				: "r"(addr), "r"((unsigned long)_new),
				  "r"((unsigned long)old)
				: "memory", "cc");

		return old_val;
	}
#endif
	}
	/* generate an illegal instruction. Cannot catch this with linker tricks
	 * when optimizations are disabled. */
	__asm__ __volatile__(ILLEGAL_INSTR);
	return 0;
}


#define uatomic_cmpxchg(addr, old, _new)				    \
	((__typeof__(*(addr))) _uatomic_cmpxchg((addr), (unsigned long)(old),\
						(unsigned long)(_new), 	    \
						sizeof(*(addr))))

/* uatomic_add_return */

static inline __attribute__((always_inline))
unsigned long _uatomic_add_return(void *addr, unsigned long val,
				 int len)
{
	switch (len) {
	case 4:
	{
		unsigned int result;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"lwarx %0,0,%1\n"	/* load and reserve */
			"add %0,%2,%0\n"	/* add val to value loaded */
			"stwcx. %0,0,%1\n"	/* store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
				: "=&r"(result)
				: "r"(addr), "r"(val)
				: "memory", "cc");

		return result;
	}
#if (BITS_PER_LONG == 64)
	case 8:
	{
		unsigned long result;

		__asm__ __volatile__(
			"lwsync\n"
		"1:\t"	"ldarx %0,0,%1\n"	/* load and reserve */
			"add %0,%2,%0\n"	/* add val to value loaded */
			"stdcx. %0,0,%1\n"	/* store conditional */
			"bne- 1b\n"	 	/* retry if lost reservation */
			"isync\n"
				: "=&r"(result)
				: "r"(addr), "r"(val)
				: "memory", "cc");

		return result;
	}
#endif
	}
	/* generate an illegal instruction. Cannot catch this with linker tricks
	 * when optimizations are disabled. */
	__asm__ __volatile__(ILLEGAL_INSTR);
	return 0;
}


#define uatomic_add_return(addr, v)					\
	((__typeof__(*(addr))) _uatomic_add_return((addr),		\
						  (unsigned long)(v),	\
						  sizeof(*(addr))))

/* uatomic_sub_return, uatomic_add, uatomic_sub, uatomic_inc, uatomic_dec */

#define uatomic_sub_return(addr, v)	uatomic_add_return((addr), -(v))

#define uatomic_add(addr, v)		(void)uatomic_add_return((addr), (v))
#define uatomic_sub(addr, v)		(void)uatomic_sub_return((addr), (v))

#define uatomic_inc(addr)		uatomic_add((addr), 1)
#define uatomic_dec(addr)		uatomic_add((addr), -1)

#define compat_uatomic_cmpxchg(ptr, old, _new)	uatomic_cmpxchg(ptr, old, _new)

#endif /* _URCU_ARCH_UATOMIC_PPC_H */