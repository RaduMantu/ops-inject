#!/bin/bash

# launch_nc_experiment.sh - starts netcat experiment
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
# NOTE: important that it is openbsd netcat
if [[ ${ADD_DEPS} -eq 1 ]]; then
    for EXT_IP in ${EXT_IPS}; do
        SSH ${EXT_IP}                               \
            "sudo apt update && sudo apt install -y \
             tcpdump netcat-openbsd dnsutils"       \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}
    done
fi

# clean up files from any previous run
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump or netcat instances
    # NOTE: script might have crased before terminating them
    SSH ${EXT_IP}                               \
        "sudo kill -9 \$(pidof netcat tcpdump)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any previous captures
    # NOTE: some files might be write protected
    SSH ${EXT_IP}           \
        "sudo rm -f *pcap" \
        "cleaning up HOME"
done

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for tcp
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-tcp-in.pcap                \
        src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and tcp \
        &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}inbound tcp${CLR} capture on ${YELLOW}%s${CLR}"  \
        ${EXT_IP}
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-tcp-out.pcap               \
        dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and tcp \
        &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}outbound tcp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
    # inbound / outbound for udp
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-udp-in.pcap                \
        src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and udp \
        &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}inbound udp${CLR} capture on ${YELLOW}%s${CLR}"  \
        ${EXT_IP}
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-udp-out.pcap               \
        dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and udp \
        &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}outbound udp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# run experiment
for EXT_IP in ${EXT_IPS}; do
    # get open ports to be used by TCP and UDP netcat servers
    TELL "getting open ports for nc servers from ${YELLOW}%s${CLR}" ${EXT_IP}
    read -r TCP_PORT UDP_PORT            \
        <<<$(SSHV ${EXT_IP}              \
                  "comm -23              \
                    <(seq 49152 65535    \
                      | sort)            \
                    <(ss -Htan           \
                      | awk '{print $4}' \
                      | cut -d':' -f2    \
                      | sort -u)         \
                   | shuf                \
                   | head -n 2           \
                   | tr '\n' ' '         \
                   2>/dev/null" 2>>${LOG_FILE})
    [[ ! -z "${TCP_PORT}" && ! -z "${UDP_PORT}" ]]
    DIE $?

    # overwrite nc ports if user provides explicit values (must be free)
    TELL "selecting open ports for experiment"
    TCP_PORT=${EXP_TCP:-${TCP_PORT}}
    UDP_PORT=${EXP_UDP:-${UDP_PORT}}
    DIE 0

    # start remote netcat servers in background
    # NOTE: check if the background processes crashed early
    SSH ${EXT_IP}                                         \
        "nohup sudo netcat -lk  ${TCP_PORT} &>/dev/null & \
         ${BG_PROCESS_CHECK}"                             \
        "starting TCP (${YELLOW}%d${CLR}) server" ${TCP_PORT}
    SSH ${EXT_IP}                                         \
        "nohup sudo netcat -ulk ${UDP_PORT} &>/dev/null & \
         ${BG_PROCESS_CHECK}"                             \
        "starting UDP (${YELLOW}%d${CLR}) server" ${UDP_PORT}

    # for each of the other instances
    for OTHER_EXT_IP in ${EXT_IPS/${EXT_IP}}; do
        # send TCP and UDP packets to current server
        SSH ${OTHER_EXT_IP}                                                 \
            "RET_IP=\$(dig +short myip.opendns.com @resolver1.opendns.com); \
             echo \"greetings from ${OTHER_EXT_IP} -- \${RET_IP}\"          \
             | netcat -w  1 ${EXT_IP} ${TCP_PORT}"                          \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (TCP)"         \
            ${OTHER_EXT_IP} ${EXT_IP}
        SSH ${OTHER_EXT_IP}                                                 \
            "RET_IP=\$(dig +short myip.opendns.com @resolver1.opendns.com); \
             echo \"greetings from ${OTHER_EXT_IP} -- \${RET_IP}\"          \
             | netcat -uw 1 ${EXT_IP} ${UDP_PORT}"                          \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (UDP)"         \
            ${OTHER_EXT_IP} ${EXT_IP}
    done

    # stop netcat processes
    SSH ${EXT_IP}                       \
        "sudo kill -9 \$(pidof netcat)" \
        "stopping netcat"
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"
done

