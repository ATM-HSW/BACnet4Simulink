#ifndef _DEBUG_MESSAGES_H_
#define _DEBUG_MESSAGES_H_

/*--------*/
/* Macros */
/*--------*/
#if defined(DEBUG)
    #if defined(SS_STDIO_AVAILABLE)
        #undef DEBUG_MSG
        #define DEBUG_MSG(X, ...) ssPrintf(X "\r\n", ##__VA_ARGS__)
    #endif
#else
    #define DEBUG_MSG(X, ...)
#endif

#endif /* _DEBUG_MESSAGES_H_ */
