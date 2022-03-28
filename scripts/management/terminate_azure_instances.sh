#!/bin/bash

# terminate_azure_instances.sh - terminates azure vm instances
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
RES_GROUP=${RES_GROUP:-'default-grp'}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}

# delete all instances in one go
TELL "deleting all instances in ${YELLOW}%s${CLR} resource group" ${RES_GROUP}
az vm delete                                                   \
    --yes                                                      \
    --ids $(az vm list -g ${RES_GROUP} --query "[].id" -o tsv) \
&>>${LOG_FILE}
DIE $?

# delete all resources in one go
TELL "deleting all resources in ${YELLOW}%s${CLR} resource group" ${RES_GROUP}
az resource delete                                                   \
    --ids $(az resource list -g ${RES_GROUP} --query "[].id" -o tsv) \
&>>${LOG_FILE}
DIE $?

