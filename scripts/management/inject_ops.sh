#!/bin/bash

# inject_ops.sh - controls options injection on remote hosts
#   $1 : [required] {setup|enable|disable}
#
#   if "setup" - prepares the tool on remote host
#   $2 : [required] ops-inject project directory
#           at the time, the git was private and this way was easier
#
#   if "enable" - configures iptables and starts injection tool
#   $2 : [required] protocol for which to inject option
#   $3 : [required] string contaning option identifier
#          example for ip NOP, TS, EOL: '\x01\x44\x00'
#
#   if "disable" - kills remote injection tools and flushes iptables rules
#
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $PROJECT  : [required] gcloud project name
#
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# cli arguments check
TELL "checking presence of command"
[[ $# -ge 1 ]]      # at least one argument (for now)
DIE $?

# extract command argument
COMMAND=${1}
shift 1

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}

# disable interactive mode (defaults will be used on prompt)
CLOUDSDK_CORE_DISABLE_PROMPTS=1

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up & prep
rm -f ${LOG_FILE}

# get external IPs of started instances
get_ext_ips

# evaluate command
TELL "identifying command"
case ${COMMAND} in
    'setup')
        DIE 0

        # check remaining argument
        TELL "checking presence of tool directory"
        [[ $# -eq 1
        && -d ${1} ]]
        DIE $?

        TOOL_DIR=${1}

        # set up environment
        for EXT_IP in ${EXT_IPS}; do
            # install dependencies
            SSH ${EXT_IP}                                                 \
                "sudo apt update && sudo apt install -y                   \
                 make gcc g++ libnetfilter-queue1 libnetfilter-queue-dev  \
                 ethtool"                                                 \
                "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}

            # clean up files from any previous run
            SSH ${EXT_IP}                        \
                "rm -rf $(basename ${TOOL_DIR})" \
                "cleaning up HOME"

            # export tool and install it
            SCP ${TOOL_DIR} ${EXT_IP}:~/ \
                "exporting tool directory"
            SSH ${EXT_IP} \
                "cd $(basename ${TOOL_DIR}) && make -j \$(nproc)" \
                "installing tool"

            # disable checksum offloading on active interface
            # just to be safe
            SSH ${EXT_IP}                                        \
                "sudo ethtool --offload                          \
                    \$(ip route get 8.8.8.8 | awk '{print \$5}') \
                    rx off tx off"                               \
                "disabling rx and tx checksum offloading"
        done

        ;;
    'enable')
        DIE 0

        # check remaining arguments
        TELL "checking presence of protocols"
        [[ $# -eq 2 ]]
        DIE $?

        OPS_PROTO=${1}
        OPS_BYTES=${2}

        for EXT_IP in ${EXT_IPS}; do
            # flush iptables rules to avoid duplicates
            SSH ${EXT_IP}                                             \
                "sudo iptables -F OUTPUT"                             \
                "flushing iptables OUTPUT rules on ${YELLOW}%s${CLR}" \
                ${EXT_IP}

            # insert accept rule for outgoing ssh traffic
            SSH ${EXT_IP}       \
                "sudo iptables  \
                    -I OUTPUT   \
                    -p tcp      \
                    --sport 22  \
                    -j ACCEPT"  \
                "inserting outgoing ssh ACCEPT all rule"

            # insert interception rules for all other hosts
            SSH ${EXT_IP}                                                 \
                "sudo iptables                                            \
                    -A OUTPUT                                             \
                    -j NFQUEUE                                            \
                    --queue-num 0                                         \
                    --queue-bypass                                        \
                    -d $(echo ${EXT_IPS/${EXT_IP}} | xargs | tr ' ' ',')" \
                "inserting iptables interception rules"

            # kill all running injectors
            SSH ${EXT_IP}                           \
                "sudo kill -9 \$(pidof ops-inject)" \
                "stopping previously running injectors"

            # start one instance of injector with specified options
            # NOTE: yes, it works; we need to escape the byte string using
            #       printf '%q' ... before sending the 'bash -c' command via
            #       ssh to the instance
            # NOTE: just assume that the tool dir name is ops-inject...
            SSH ${EXT_IP}                                        \
                "nohup sudo bash -c './ops-inject/bin/ops-inject \
                    -p ${OPS_PROTO}                              \
                    -q 0                                         \
                    -w                                           \
                    <(printf $(printf '%q' ${OPS_BYTES}))'       \
                 &>injector.log &                                \
                 ${BG_PROCESS_CHECK}"                            \
                "starting ${YELLLOW}%s${CLR} injector" ${OPS_PROTO}
        done

        ;;
    'disable')
        DIE 0

        for EXT_IP in ${EXT_IPS}; do
            # flush iptables rules to avoid duplicates
            SSH ${EXT_IP}                                             \
                "sudo iptables -F OUTPUT"                             \
                "flushing iptables OUTPUT rules on ${YELLOW}%s${CLR}" \
                ${EXT_IP}

            # kill all running injectors
            SSH ${EXT_IP}                           \
                "sudo kill -9 \$(pidof ops-inject)" \
                "stopping previously running injectors"
        done

        ;;
    *)
        DIE 1
esac

