#!/bin/bash

# launch_ntp_experiment - starts ntp experiment
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $OUT_DIR  : [optional] output dir for logs         (has default)
#   $ADD_DEPS : [optional] if 1 installs dependencies  (has default)
#   $EXP_UDP  : [optional] explicit udp port override
#   $EXP_TCP  : [optional] explicit tcp port override
#
# NOTE: check util.sh for additional environment arguments

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

# get external IPs of started instances
get_ext_ips

# install dependencies
if [[ ${ADD_DEPS} -eq 1 ]]; then
    for EXT_IP in ${EXT_IPS}; do
        # another workaround for some tzdata fuckery
        SSH ${EXT_IP}                                                         \
            "sudo ln -snf /usr/share/zoneinfo/Europe/Bucharest /etc/localtime \
             && sudo bash -c 'echo Europe/Bucharest > /etc/timezone'"         \
            "resolving possible timezone problems"

        # apt install may block due to tzdata; hence, DEBIAN_FRONTEND
        SSH ${EXT_IP}                                           \
            "sudo apt update &&                                 \
             DEBIAN_FRONTEND=noninteractive sudo apt install -y \
             tcpdump ntp ntpdate"                               \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}
    done
fi

# clean up files from any previous run
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump instances
    # NOTE: script might have crased before terminating them
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any previous captures
    # NOTE: some files might be write protected
    SSH ${EXT_IP}          \
        "sudo rm -f *pcap" \
        "cleaning up HOME"
done

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for ntp
    SSH ${EXT_IP}                                                          \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-ntp-in.pcap               \
        src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and    \
        port 123 &>/dev/null &                                             \
        ${BG_PROCESS_CHECK}"                                               \
        "starting ${YELLOW}inbound ntp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-ntp-out.pcap               \
        dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and     \
        port 123 &>/dev/null &                                              \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}outbound ntp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# run experiment
for EXT_IP in ${EXT_IPS}; do
    # make sure that ntp service is started (don't bother stopping it later)
    SSH ${EXT_IP}                \
        "sudo service ntp start" \
        "starting ${YELLOW}ntpd${CLR} on ${YELLOW}%s${CLR}" ${EXT_IP}

    # for each of the other instances
    for OTHER_EXT_IP in ${EXT_IPS/${EXT_IP}}; do
        # send ntp query but don't update system time
        SSH ${OTHER_EXT_IP}                                         \
            "ntpdate -qt 5 ${EXT_IP}"                               \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (NTP)" \
            ${OTHER_EXT_IP} ${EXT_IP}
    done
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"
done

