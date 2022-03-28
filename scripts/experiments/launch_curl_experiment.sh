#!/bin/bash

# launch_http_experiment.sh - starts http experiment
#   $1 : [required] file with domains / IPs of http servers (one per line)
#
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $OUT_DIR  : [optional] output dir for logs         (has default)
#
# must have previously launched up to 6 instances using launch_instace.sh
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# cli arguments check
TELL "checking script argumnets"
[[ $# -eq 1         # single argument
&& -f $1 ]]         # domains file exists
DIE $?

# rename cli arguments
DOMAINS_FILE=${1}

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}
OUT_DIR=${OUT_DIR:-'logs'}

OUT_DIR=${OUT_DIR%/}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up & prep
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# get external IPs of started instances
get_ext_ips

# clean up files from any previous run & load dependencies
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump instances
    # NOTE: script might have crased before terminating them
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any previous captures
    # NOTE: some files might be write protected
    SSH ${EXT_IP}               \
        "sudo rm -f *pcap *log" \
        "cleaning up HOME"

    # export file with domains to server
    # NOTE: list go from moz.com on 26-Apr-2021
    SCP ${DOMAINS_FILE} ${EXT_IP}:~/ \
        "exporting domains file"
done

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for tcp port 80 or 443
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-curl-in.pcap               \
         dst ${EXT_IP} and tcp src port '(80 or 443)'                       \
         &>/dev/null &                                                      \
         ${BG_PROCESS_CHECK}"                                               \
        "starting ${YELLOW}inbound http${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
    SSH ${EXT_IP}                                                            \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-curl-out.pcap               \
         src ${EXT_IP} and tcp dst port '(80 or 443)'                        \
         &>/dev/null &                                                       \
         ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}outbound http${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# for each instance started
for EXT_IP in ${EXT_IPS}; do
    # run individual experiments as parallel groups in backround
    # NOTE: we can get better debug info if we run these sequentially
    #       or if we provide separate logging files
    TELL "starting detached experiment for ${YELLOW}%s${CLR}" ${EXT_IP}
    {
        # run curl on remote server
        # NOTE: follow redirect but time out connection phase after N secs
        # NOTE: do not use strict certificate verification for https
        SSHV ${EXT_IP} \
             "rm -f curl.log
              while read -r DOMAIN; do
                 curl -Lk -m 10 \${DOMAIN} &>/dev/null
                 ANS=\$?
                 if [ \${ANS} -eq 6 ]; then
                     curl -Lk -m 10 www.\${DOMAIN} &>/dev/null
                     ANS=\$?
                 fi

                 printf '%-32s -- %3d\n' \${DOMAIN} \${ANS} \
                 &>>curl-${EXT_IP}.log
             done <$(basename ${DOMAINS_FILE})" \
             &>>/dev/null
    } &
    sleep 1s; kill -0 $!
    DIE 0
done

# wait for started jobs to finish
TELL "waiting for jobs to finish"
wait < <(jobs -p)
DIE $?

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"

    SCP ${EXT_IP}:~/curl\*log ${OUT_DIR} \
        "copying summary logs to localhost"
done

