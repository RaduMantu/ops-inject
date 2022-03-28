#!/bin/bash

# vpn_manager.sh - controls vpn settings on remote hosts
#   $1 : [required] {setup|export|enable|disable}
#
#   if "setup" - installs dependencies on remote host (openvpn)
#
#   if "export" - copies vpngate config file for openvpn to remote host
#   $2 : [required] openvpn config file from vpngate
#
#   if "enable" - starts openvpn on each remote host with explicit routes to
#                 all other hosts only
#   $2 : [required] name of config file (copied with "export") to be used
#
#   if "disable" - kills openvpn instances on all remote hosts
#
#   $LOG_FILE : [optional] log file for api call outputs (has default)
#
# NOTE: in the end, we didn't do much vpn testing due to time constraints, so
#       be particularly careful when using this
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

        # install deps
        for EXT_IP in ${EXT_IPS}; do
            SSH ${EXT_IP}                                        \
                "sudo apt update && sudo apt install -y openvpn" \
                "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}
        done

        ;;
    'export')
        DIE 0

        # check remaining argument
        TELL "checking presence of openvpn config file"
        [[ $# -eq 1
        && -f ${1} ]]
        DIE $?

        CONFIG_FILE=${1}

        # copy config file
        for EXT_IP in ${EXT_IPS}; do
            SCP ${CONFIG_FILE} ${EXT_IP}:~/ \
                "exporting config file to ${YELLOW}%s${CLR}" ${EXT_IP}
        done

        ;;
    'enable')
        DIE 0

        # check remaining argument
        TELL "checking presence of config file arg"
        [[ $# -eq 1 ]]
        DIE $?

        CONFIG_FILE=${1}

        # start openvpn on all hosts (give it some time to init after it's done)
        for EXT_IP in ${EXT_IPS}; do
            # create custom command
            OVPN_COMM="sudo openvpn --config ${CONFIG_FILE} --route-nopull"
            OVPN_COMM="${OVPN_COMM} $(echo ${EXT_IPS/${EXT_IP}} \
                                      | xargs -n1 printf ' --route %s')"

            # execute command on remote
            SSH ${EXT_IP}                  \
                "${OVPN_COMM} &>ovpn.log & \
                 ${BG_PROCESS_CHECK}"      \
                "starting openvpn instance on ${YELLOW}%s${CLR}" ${EXT_IP}
        done

        ;;
    'disable')
        DIE 0

        # stop openvpn on all instances
        for EXT_IP in ${EXT_IPS}; do
            SSH ${EXT_IP}                    \
            "sudo kill -9 \$(pidof openvpn)" \
            "stopping openvpn on ${YELLOW}%s${CLR}" ${EXT_IP}
        done

        ;;
    *)
        DIE 1
esac

