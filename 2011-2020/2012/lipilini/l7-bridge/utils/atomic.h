#ifndef _ATOMIC_H
#define _ATOMIC_H

#define ATOMIC_INCR(var)  __sync_fetch_and_add((var), 1)
#define ATOMIC_DECR(var)  __sync_fetch_and_sub((var), 1)

#define ATOMIC_ADD(var, value)  __sync_fetch_and_add((var), (value))
#define ATOMIC_SUB(var, value)  __sync_fetch_and_sub((var), (value))

#define ATOMIC_CAS(var, oldval, newval)   __sync_bool_compare_and_swap((var), (oldval), (newval))

#define ATOMIC_TSL(var)   __sync_lock_test_and_set((var), 1)
#define ATOMIC_RL(var)    __sync_lock_release ((var))

#endif // _ATOMIC_H
