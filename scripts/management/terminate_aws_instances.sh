#!/bin/bash

# terminate_aws_instances.sh - terminates aws instances in all areas
#   $LOG_FILE : [optional] log file for aws outputs (has default)
#   $OUT_DIR  : [optional] output dir for logs      (has defualt)
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
OUT_DIR=${OUT_DIR:-'logs'}

# disable output pager (default is less)
export AWS_PAGER=""

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# for each individual region
for REGION in $(aws ec2 describe-regions           \
                    --query 'Regions[].RegionName' \
                    --output text                  \
                2>>${LOG_FILE}); do
    TELL "scanning region ${YELLOW}%s${CLR} for instances" ${REGION}; echo

    # for each instance
    for INSTANCE in $(aws ec2 describe-instances                           \
                        --query 'Reservations[*].Instances[*].InstanceId'  \
                        --filter 'Name=instance-state-name,Values=running' \
                        --output text                                      \
                        --region ${REGION}                                 \
                      2>>${LOG_FILE}); do
        TELL "terminating instance ${YELLOW}%s${CLR}" ${INSTANCE} 
        aws ec2 terminate-instances     \
            --region ${REGION}          \
            --instance-ids ${INSTANCE}  \
            &>>${LOG_FILE}
        DIE $?
    done
done
 
