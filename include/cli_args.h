#include <argp.h>
#include <stdint.h>

#ifndef _CLI_ARGS_H
#define _CLI_ARGS_H

/* structure holding arguments information */
struct arguments
{
    uint16_t q_num;         /* queue number             */
    uint16_t nq_num;        /* next queue number        */
    uint8_t  redirect;      /* queue redirection        */
    uint8_t  overwrite;     /* !0 to overwrite ops      */
    uint8_t  *ops;          /* user specified options   */
    size_t   ops_len;       /* length in bytes of ops   */
    
    /* protocol specific options decoder & packet reassembler */
    size_t (*decoder)(struct iphdr *iph, void **ops_buffer, uint8_t ow);
    int (*reasmbl)(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
        size_t ops_len, uint8_t ow);
};

extern struct argp      argp;
extern struct arguments args;

#endif

