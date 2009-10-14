/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (c) 2009 Mathieu Desnoyers
 */

/* 16 CPUs max (byte has 8 bits, divided in two) */

#ifndef CONFIG_BITS_PER_BYTE
#define BITS_PER_BYTE		8
#else
// test progress failure with shorter byte size. Will fail with 5 proc.
#define BITS_PER_BYTE		CONFIG_BITS_PER_BYTE
#endif

#define HBPB			(BITS_PER_BYTE / 2)	/* 4 */
#define HMASK			((1 << HBPB) - 1)	/* 0x0F */

/* for byte type */
#define LOW_HALF(val)		((val) & HMASK)
#define LOW_HALF_INC		1

#define HIGH_HALF(val)		((val) & (HMASK << HBPB))
#define HIGH_HALF_INC		(1 << HBPB)

byte lock = 0;
byte refcount = 0;

#define need_pause()	(_pid == 2)

/*
 * Test weak fairness by either not pausing or cycling for any number of
 * steps, or forever.
 * Models a slow thread. Should be added between each atomic steps.
 * To test for wait-freedom (no starvation of a specific thread), add do_pause
 * in threads other than the one we are checking for progress (and which
 * contains the progress label).
 * To test for lock-freedom (system-wide progress), add to all threads except
 * one. All threads contain progress labels.
 */
inline do_pause()
{
	if
	:: need_pause() ->
		do
		:: 1 ->
			skip;
		od;
	:: 1 ->
		skip;
	fi;
}

inline spin_lock(lock, ticket)
{
	atomic {
		ticket = HIGH_HALF(lock) >> HBPB;
		lock = lock + HIGH_HALF_INC;	/* overflow expected */
	}

	do
	:: 1 ->
		if
		:: (LOW_HALF(lock) == ticket) ->
			break;
		:: else ->
			skip;
		fi;
	od;
}

inline spin_unlock(lock)
{
	lock = HIGH_HALF(lock) | LOW_HALF(lock + LOW_HALF_INC);
}

proctype proc_A()
{
	byte ticket;

	do
	:: 1 ->
progress_A:
		spin_lock(lock, ticket);
		refcount = refcount + 1;
		refcount = refcount - 1;
		spin_unlock(lock);
	od;
}

proctype proc_B()
{
	byte ticket;

	do
	:: 1 ->
		do_pause();
		spin_lock(lock, ticket);
		refcount = refcount + 1;
		do_pause();
		refcount = refcount - 1;
		spin_unlock(lock);
	od;
}

init
{
	run proc_A();
	run proc_B();
	run proc_B();
	run proc_B();
	run proc_B();
}
