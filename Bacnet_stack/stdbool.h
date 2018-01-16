#ifndef _STDBOOL_H
#define _STDBOOL_H

#include <stdint.h>
/* C99 Boolean types for compilers without C99 support */

#ifndef __cplusplus
//typedef char _Bool;
#ifndef bool
#define bool _Bool
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#define __bool_true_false_are_defined 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif
/* C99 Boolean types for compilers without C99 support */
/* http://www.opengroup.org/onlinepubs/009695399/basedefs/stdbool.h.html */
#if !defined(__cplusplus)

#if !defined(__GNUC__)
/* _Bool builtin type is included in GCC */
/* ISO C Standard: 5.2.5 An object declared as 
   type _Bool is large enough to store 
   the values 0 and 1. */
/* We choose 8 bit to match C++ */
/* It must also promote to integer */
#if _MSC_VER < 1600
typedef int8_t _Bool;
#endif /* _MSC_VER < 1600 VS 2010 and earlier */
#endif

/* ISO C Standard: 7.16 Boolean type */
#ifndef bool
#define bool _Bool
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
#define __bool_true_false_are_defined 1

#endif

#endif
