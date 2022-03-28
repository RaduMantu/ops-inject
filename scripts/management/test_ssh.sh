#!/bin/bash

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# get external IPs of started instances
get_ext_ips

# try to ssh into each host
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}   \
        "uname -a"  \
        "testing connectivity to ${YELLOW}%s${CLR}" ${EXT_IP}
done

