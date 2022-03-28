#!/bin/bash

# launch_tfo_experiment.sh - starts tcp fast open experiment
#   $1 : [required] tfoecho directory
#
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $OUT_DIR  : [optional] gcloud dir for logs         (has default)
#   $ADD_DEPS : [optional] if 1 installs dependencies  (has default)
#
# NOTE: check util.sh for additional environment arguments
# NOTE: we are using https://github.com/yuryu/tfoecho.git tfoecho
#       but added a timeout option on socket read/write
#
# what you need to look for in a .pcap to check that it works:
#   >SYN, <SYN|ACK, >PSH|ACK            ( > is client to server )
# in stead of the usual
#   >SYN, <SYN|ACK, >ACK, >PSH|ACK      ( < is server to client )

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}
OUT_DIR=${OUT_DIR:-'logs'}
ADD_DEPS=${ADD_DEPS:-1}

OUT_DIR=${OUT_DIR%/}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up & prep
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# check argument
TELL "checking presence of modified tfoecho tool"
[[ $# -eq 1
&& -d ${1} ]]
DIE $?

TFO_DIR=${1}

# get external IPs of started instances
get_ext_ips

# clean up files from any previous run
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump or tcpfo server instances
    # NOTE: script might have crased before terminating them
    SSH ${EXT_IP}                               \
        "sudo kill -9 \$(pidof tcpdump server)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any previous captures
    SSH ${EXT_IP}                   \
        "sudo rm -rf *pcap tfoecho" \
        "cleaning up HOME"
done

# install dependencies
if [[ ${ADD_DEPS} -eq 1 ]]; then
    for EXT_IP in ${EXT_IPS}; do
        SSH ${EXT_IP}                               \
            "sudo apt update && sudo apt install -y \
             tcpdump git g++ make"                  \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}

        SCP ${TFO_DIR} ${EXT_IP}:~/ \
            "exporting tool directory"

        SSH ${EXT_IP}                                                \
            "cd tfoecho; make -j \$(nproc)"                          \
            "setting up tfoecho server/client on ${YELLOW}%s${CLR}" ${EXT_IP}

        SSH ${EXT_IP}                                                 \
            "sudo bash -c 'echo 3 > /proc/sys/net/ipv4/tcp_fastopen'" \
            "enabling TCP-FO support on ${YELLOW}%s${CLR}" ${EXT_IP}
    done
fi

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for tcp port 32345
    SSH ${EXT_IP}                                                            \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-tcpfo-in.pcap               \
        src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g')          \
        and port 32345 &>/dev/null &                                         \
        ${BG_PROCESS_CHECK}"                                                 \
        "starting ${YELLOW}inbound tcpfo${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
    SSH ${EXT_IP}                                                             \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-tcpfo-out.pcap               \
        dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g')           \
        and port 32345 &>/dev/null &                                          \
        ${BG_PROCESS_CHECK}"                                                  \
        "starting ${YELLOW}outbound tcpfo${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# for each instance started
for EXT_IP in ${EXT_IPS}; do
    # start remote TCP Fast Open servers in background
    # NOTE: servers use port 32345 by default
    SSH ${EXT_IP}                             \
        "nohup ./tfoecho/server &>/dev/null & \
         ${BG_PROCESS_CHECK}"                 \
        "starting remote TCP-FO server on ${YELLOW}%s${CLR}" ${EXT_IP}

    # for each of the other instances
    for OTHER_EXT_IP in ${EXT_IPS/${EXT_IP}}; do
        # send 1024 bytes via TCP w/ Fast Open option, twice
        SSH ${OTHER_EXT_IP}                                            \
            "./tfoecho/client ${EXT_IP} 1024 2 1"                      \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (TCP-FO)" \
            ${OTHER_EXT_IP} ${EXT_IP}
    done

    # stop TCP Fast Open server
    SSH ${EXT_IP}                       \
        "sudo kill -9 \$(pidof server)" \
        "stopping TCP-FO server"
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"
done

