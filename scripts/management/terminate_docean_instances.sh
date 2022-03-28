#!/bin/bash

# terminate_docean_instances.sh - terminate digital ocean vm instances
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}

# for each instance id
while read -r INST_ID INST_NAME; do
    # delete instance
    TELL "deleting instance ${YELLOW}%s${CLR}" ${INST_NAME}
    doctl compute droplet delete --force ${INST_ID} \
        &>>${LOG_FILE}
    DIE $?
done <<< $(doctl compute droplet list --format ID,Name --no-header)

