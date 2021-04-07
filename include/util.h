#include <stdio.h>      /* fprintf */
#include <stdlib.h>     /* exit    */
#include <errno.h>      /* errno   */

#ifndef _UTIL_H
#define _UTIL_H

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CLR     "\033[0m"

/* quality of life - return code checker */
#define DIE(assertion, msg...)                                  \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            exit(-1);                                           \
        }                                                       \
    } while(0)

/* quality of life - jump to cleanup label */
#define ABORT(assertion, label, msg...)                         \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            goto label;                                         \
        }                                                       \
    } while (0)

/* quality of life - immediate return */
#define RET(assertion, code, msg...)                            \
    do {                                                        \
        if (assertion) {                                        \
            fprintf(stderr, RED "%s:%d ", __FILE__, __LINE__);  \
            fprintf(stderr, msg);                               \
            fprintf(stderr, CLR "\n");                          \
            return code;                                        \
        }                                                       \
    } while (0)

#endif

