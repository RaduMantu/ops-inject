#!/bin/bash

# terminate_gcloud_instances.sh - terminates gcloud vm instances
#   $PROJECT  : [required] gcloud project name
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
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
API_VERS=${API_VERS:-'beta'}

# disable interactive mode (defaults will be used on prompt)
CLOUDSDK_CORE_DISABLE_PROMPTS=1

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}

# for each pair of (instance_name, instance_zone)
# TODO: figure out why the loop breaks after each successful deletion
while read -r INST_NAME INST_ZONE; do
    # delete instance (must specify zone and disks to destroy)
    TELL "deleting instance ${YELLOW}%s${CLR}" ${INST_NAME}
    gcloud ${API_VERS} compute instances delete ${INST_NAME} \
        --project ${PROJECT}                                 \
        --quiet                                              \
        --zone ${INST_ZONE}                                  \
        --delete-disks all                                   \
        &>>${LOG_FILE}
    DIE $?
done <<< $(gcloud ${API_VERS} compute instances list \
           | tail -n +2                              \
           | awk '{print $1" "$2}')

