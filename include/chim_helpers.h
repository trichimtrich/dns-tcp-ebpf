// IMPORTANT
#define __KERNEL__
#define KBUILD_MODNAME "chim"
// kconfig is from bcc frontend cflags

#include <linux/kconfig.h>
#include <linux/types.h>

// Extract from bcc helpers
// https://github.com/iovisor/bcc/issues/2546

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
