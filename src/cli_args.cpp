#include <string.h>         /* strncmp                   */
#include <sys/stat.h>       /* fstat                     */
#include <errno.h>          /* errno                     */
#include <stdlib.h>         /* malloc                    */
#include <fcntl.h>          /* open                      */
#include <unistd.h>         /* read, close               */

#include "util.h"           /* DIE, ABORT, RET           */
#include "decoders.h"       /* protocol options decoders */
#include "reassemblers.h"   /* packet reassemblers       */
#include "cli_args.h"

/* command line arguments */
static struct argp_option options[] = {
    { "proto",     'p', "{ip|tcp|udp}", 0,
      "Target protocol" },
    { "queue",     'q', "NUM", 0,
      "Netfilter queue number"},
    { "redirect",  'r', "NUM", 0,
      "Target queue redirection (default: disabled)" },
    { "overwrite", 'w', NULL, 0,
      "Overwrite existing ops (default: no)" },
    { 0 }
};

/* argument parser prototype */
static error_t parse_opt(int, char *, struct argp_state *);

/* description of accepted non-option arguments */
static char args_doc[] = "FILE";

/* program documentation */
static char doc[] = "ops-inject -- injects user defined ops into specific headers";

/* declaration of relevant structures */
struct argp      argp = { options, parse_opt, args_doc, doc };
struct arguments args = {
    .q_num     = 0,
    .nq_num    = 0,
    .redirect  = 0,
    .overwrite = 0,
    .ops       = NULL,
    .ops_len   = 0,
    .decoder   = NULL,
    .reasmbl   = NULL,
};

/* parse_opt - parses one argument and updates relevant structures
 *  @key   : argument id
 *  @arg   : pointer to the actual argument
 *  @state : parsing state
 *
 *  @return : 0 if everything ok
 */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct stat statbuf;
    int         fd, ans;
    ssize_t     rb;

    switch (key) {
        /* protocol */
        case 'p':
            if (!strncmp(arg, "ip", 3)) {
                args.decoder = decode_ip_ops;
                args.reasmbl = reassemble_ip;
            } else if (!strncmp(arg, "tcp", 4)) {
                args.decoder = decode_tcp_ops;
                args.reasmbl = reassemble_tcp;
            } else if (!strncmp(arg, "udp", 4)) {
                args.decoder = decode_udp_ops;
                args.reasmbl = reassemble_udp;
            } else
                return ARGP_ERR_UNKNOWN;
            break;
        /* queue number */
        case 'q':
            sscanf(arg, "%hd", &args.q_num);
            break;
        /* queue redirection number */
        case 'r':
            sscanf(arg, "%hd", &args.nq_num);
            args.redirect = 1;
            break;
        /* force */
        case 'w':
            args.overwrite = 1;
            break;
        /* user's ops file */
        case ARGP_KEY_ARG:
            /* read uninterpreted ops into memory */
            fd = open(arg, O_RDONLY);
            DIE(fd == -1, "Check ops file path or permissions (%d)", errno);

            ans = fstat(fd, &statbuf);
            DIE(ans == -1, "Unable to stat open file (%d)", errno);

            /* in case of subshell stdout substitution, st_size will be 0 *
             * give the buffer an arbitrary larger size by faking st_size */
            statbuf.st_size = 1024;

            args.ops = (uint8_t *) malloc(statbuf.st_size);
            DIE(!args.ops, "Unable to allocate memory (%d)", errno);

            rb = read(fd, args.ops, statbuf.st_size);
            DIE(rb == -1, "Unable to read ops file (%d)", errno);
            DIE(rb == 0,  "No ops specified in given file");

            ans = close(fd);
            DIE(ans == -1, "Unable to close ops file (%d)", errno);

            args.ops_len = rb;
            
            break;
        /* unknown argument */
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

