# util.sh - source this for functions and conig variables
#   $CHR_WIDTH : [optional] right padding length             (has default)
#   $MSG_SUCC  : [optional] mark for successful evaluation   (has default)
#   $MSG_FAIL  : [optional] mark for catastrophic failure    (has default)
#   $MSG_MEEH  : [optional] mark for inconsequential failure (has default)
#
# NOTE: if you import these values, make sure you don't have conflicting names


###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################
 
# ANSI color escape codes
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CLR="\033[0m"

# default values
CHR_WIDTH=${CHR_WIDTH:-70}
MSG_SUCC=${MSG_SUCC:-"${GREEN}done${CLR}"}
MSG_FAIL=${MSG_FAIL:-"${RED}failed${CLR}"}
MSG_MEEH=${MSG_MEEH:-"${YELLOW}skipped${CLR}"}

# ssh cheat commands (insert into the command itself)
# BG_PROCESS_CHECK - adding this after launching a process in background will
#                    check after a small delay if the process is still alive.
#                    'kill -0' must be the final command that is executed on
#                    the remote host for the error code to propagate. this can
#                    be arranged if you run 'set -e' beforehand (as in SSH)
BG_PROCESS_CHECK='sleep 1s; sudo kill -0 $!'

# reserved variables
CHR_WR=0

###############################################################################
############################## UTILITY FUNCTIONS ##############################
###############################################################################

# TELL - equivalent to timestamped printf
#   $@ : [required] arguments of a printf
#
#   $CHR_WR : [return] number of visible characters written
function TELL {
    # construct output w/ timestamp
    local TIMESTAMP="$(printf "[${BLUE}%s${CLR}]" $(date '+%H:%M:%S'))"
    local MESSAGE="$(printf "$@")"

    local OUTPUT="${TIMESTAMP} ${MESSAGE}"

    # display output & get number of visible characters written
    echo -n ${OUTPUT}
    CHR_WR=$(printf "${OUTPUT}" | sed 's,\x1B\[[0-9;]*m,,g' | wc -c)
}

# DIE - evaluats return value and terminates if !0
#   $1 : [required] previous command return value
#   $2 : [optional] error message
#
# must match a TELL call:
#   $ TELL "going to do something"
#   $ do_something
#   $ DIE $?
function DIE {
    # calculate remaining right pad length
    local FILL_COUNT=$((CHR_WIDTH - CHR_WR))

    # format error message if any
    local ERR_MSG=''
    if [ ! -z "$2" ]; then
        ERR_MSG="    ${RED}$2${CLR}\n" 
    fi

    # print padding and result
    printf ' '
    printf '.%.0s' $(seq ${FILL_COUNT})
    (($1 == 0))                         \
    && printf " ${MSG_SUCC}\n"          \
    || (printf " ${MSG_FAIL} (%d)\n" $1 \
        && printf "${ERR_MSG}"          \
        && exit -1)
}

# WAR - like DIE but without terminating
#   $1 : [required] previous command return value
#   $2 : [optional] error message
#
# must match a TELL call
function WAR {
    # calculate remaining right pad length
    local FILL_COUNT=$((CHR_WIDTH - CHR_WR))

    # format error message if any
    local ERR_MSG=''
    if [ ! -z "$2" ]; then
        ERR_MSG="    ${YELLOW}$2${CLR}\n" 
    fi

    # print padding and result
    printf ' '
    printf '.%.0s' $(seq ${FILL_COUNT})
    (($1 == 0))                 \
    && printf " ${MSG_SUCC}\n"  \
    || (printf " ${MSG_MEEH}\n" \
        && printf "${ERR_MSG}")
}

###############################################################################
######################### PROJECT SPECIFIC FUNCTIONS ##########################
###############################################################################

# SSHV - vanilla wrapper over ssh w/ special settings
#   $1 : [required] [user@]host
#   $2 : [required] remote command
#
# use this in stead of SSH when you need to use the generated output
# 'set -e' will not be used by default
#
# NOTE: the actual ssh command must be the last one in the function so that it
#       can be used with DIE
function SSHV {
    # ssh w/o strict known host checking
    # NOTE: StrictHostKeyChecking is useless when used with the other options
    #       but better to be safe
    ssh -o 'StrictHostKeyChecking=no'       \
        -o 'UserKnownHostsFile=/dev/null'   \
        -o 'GlobalKnownHostsFile=/dev/null' \
        "$@" 
}

# SSH - interactive wrapper over TELL, ssh, DIE w/ special settings
#   $1    : [required] [user@]host
#   $2    : [required] remote command
#   $3..N : [required] intention message for TELL
#
#   LOG_FILE : [required] output file for ssh stdout / stderr
#
# NOTE: exit code 255 means error with ssh itself
#       other exit codes are passed by the last executed remote command
#       'set -e' 
function SSH {
    # consume first two arguments
    REMOTE_TARGET=$1
    REMOTE_COMM="set -e; $2"
    shift 2

    # display debug message using rest of arguments
    TELL "$@"

    # set immediate exit on error in remote shell
    SSHV ${REMOTE_TARGET} ${REMOTE_COMM} &>>${LOG_FILE}
    DIE $?
}

# SCPV - vanila wrapper over scp w/ special settings
#   $1 : [required] [user@]host:file1
#   $2 : [required] [user@]host:file2
#
# use this in stead of SCP when you want to avoid using TELL/DIE
# for example in background running groups (see curl experiment)
#
# NOTE: the actual scp command must be the last one in the function so that it
#       can be used with DIE
function SCPV {
    # set immediate exit on error in remote shell
    scp -o 'StrictHostKeyChecking=no'       \
        -o 'UserKnownHostsFile=/dev/null'   \
        -o 'GlobalKnownHostsFile=/dev/null' \
        -r $1 $2 
}

# SCP - interactive wrapper over TELL, scp, DIE w/ special settings
#   $1    : [required] [user@]host:file1
#   $2    : [requried] [user@]host:file2
#   $3..N : [required] intention message for tell
#
#   LOG_FILE : [required] output file for scp stdout / stderr
#
# NOTE: this operation does not have a vanilla correspondent (no need)
function SCP {
    # consume first two arguments
    FILE1=$1
    FILE2=$2
    shift 2

    # display debug message using rest of arguments
    TELL "$@"
    SCPV ${FILE1} ${FILE2} &>>${LOG_FILE}
    DIE $?
}

