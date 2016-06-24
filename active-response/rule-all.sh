#!/usr/bin/env bash
# Author: Jon Schipp
CHAT=/usr/local/bin/ircsay
PROG=OSSEC
SCRIPT=$0
CHANNEL="#ossec-alerts"
MAIL=user@org
ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

# Exit just in case we mess up the config and receive a syscheck alert
[[ "$*" =~ syscheck ]] && exit

# This scripts calls others because only one can be executed by OSSEC

die(){
  if [ -f ${COWSAY:-none} ]; then
    $COWSAY -d "$*"
  else
    printf "$*\n"
  fi
  exit 0
}

is_ip(){
  [[ $IP ]] || return 1
  [[ $IP == '-' ]] && return 1
  return 0
}

# Set paths of launchable active-response scripts
LOCAL=$(dirname $0);
cd $LOCAL
cd ../
PWD=$(pwd)
CHAT="$PWD/bin/alert2chat.sh"
CIF="$PWD/bin/cif.sh"
BHR="$PWD/bin/bhr.sh"
CDB="$PWD/bin/add_to_cdb.sh"
CMDS="$PWD/bin/command_search.sh"
TS="$PWD/bin/time_lookup.sh"
LDAP="$PWD/bin/ldap_lookup.sh"

printf "$(date) $0 $ACTION $USER $IP $ALERTID $RULEID $6 $7 $8\n" >> ${PWD}/../logs/active-responses.log

# Chat
[[ -x $CHAT ]] && $CHAT $ACTION $USER $IP $ALERTID $RULEID

# Collect system user accounts from 'new user' events, only work on rule 5902
[[ -x $CDB ]] && [[ $RULEID -eq 5902 ]] && $CDB $ACTION $USER $IP $ALERTID $RULEID

# Search for suspicious commands
[[ -x $CMDS ]] && $CMDS $ACTION $USER $IP $ALERTID $RULEID

# Check if system's clock is off
[[ -x $TS ]] && $TS $ACTION $USER $IP $ALERTID $RULEID

# Lookup user's in LDAP
[[ -x $LDAP ]] && $LDAP $ACTION $USER $IP $ALERTID $RULEID

# CIF Feed
is_ip && [[ -x $CIF ]] && $CIF $ACTION $USER $IP $ALERTID $RULEID

# BHR Block
is_ip && [[ -x $BHR ]] && $BHR $ACTION $USER $IP $ALERTID $RULEID
