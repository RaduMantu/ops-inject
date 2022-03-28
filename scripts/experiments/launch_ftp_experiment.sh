#!/bin/bash

# launch_ftp_experiment.sh - start ftp experiment
#   $1 : [required] vsftpd.conf
#
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $OUT_DIR  : [optional] output dir for logs         (has default)
#   $ADD_DEPS : [optional] if 1 installs dependencies  (has default)
#   $SRV_PORT : [optional] http server port            (has default)
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
SRV_PORT=${SRV_PORT:-80}

OUT_DIR=${OUT_DIR%/}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up & prep
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# check argument
TELL "checking presence of vsftpd.conf"
[[ $# -eq 1
&& -f ${1} ]]
DIE $?

FTP_CONF=${1}

# get external IPs of started instances
get_ext_ips

# clean up files from any previous run
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump or python instances
    # NOTE: script might have crased before terminating them
    SSH ${EXT_IP}                               \
        "sudo kill -9 \$(pidof vsftpd tcpdump)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any previous captures
    # NOTE: some files might be write protected
    SSH ${EXT_IP}                      \
        "sudo rm -f *pcap ${FTP_CONF}" \
        "cleaning up HOME"
done

# install dependencies
if [[ ${ADD_DEPS} -eq 1 ]]; then
    for EXT_IP in ${EXT_IPS}; do
        SSH ${EXT_IP}                               \
            "sudo apt update && sudo apt install -y \
             tcpdump vsftpd lftp"                   \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}

        SCP ${FTP_CONF} ${EXT_IP}:~/ \
            "exporting vsftpd.conf"

        SSH ${EXT_IP}                                      \
            "sudo chown root:root $(basename ${FTP_CONF})" \
            "setting root ownership of vsftpd.conf"
    done
fi

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for given port
    SSH ${EXT_IP}                                                          \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-ftp-in.pcap               \
        src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and    \
        port 21 &>/dev/null &                                              \
        ${BG_PROCESS_CHECK}"                                               \
        "starting ${YELLOW}inbound tcp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
    SSH ${EXT_IP}                                                           \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-ftp-out.pcap               \
        dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and     \
        port 21 &>/dev/null &                                               \
        ${BG_PROCESS_CHECK}"                                                \
        "starting ${YELLOW}outbound tcp${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# run experiment
for EXT_IP in ${EXT_IPS}; do
    # make absolutely sure that vsftpd is not running
    SSH ${EXT_IP}                                     \
        "sudo pkill vsftpd; sudo service vsftpd stop" \
        "making sure vsftpd is not running on ${YELLOW}%s${CLR}" ${EXT_IP}

    # start ftp server
    SSH ${EXT_IP}                                                \
        "nohup sudo vsftpd $(basename ${FTP_CONF}) &>/dev/null & \
        ${BG_PROCESS_CHECK}"                                     \
        "starting vsftpd"

    # for each of the other instances
    for OTHER_EXT_IP in ${EXT_IPS/${EXT_IP}}; do
        # send lftp ls request on port 21
        # NOTE: use timeout; might get stuck when using tcp options
        SSH ${OTHER_EXT_IP}                                         \
            "timeout 5s lftp -e 'ls;quit' ${EXT_IP} 21"             \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (FTP)" \
            ${OTHER_EXT_IP} ${EXT_IP}
    done

    # stop vsftpd
    SSH ${EXT_IP}                       \
        "sudo kill -9 \$(pidof vsftpd)" \
        "stopping vsftpd server"
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"
done

