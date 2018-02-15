#!/bin/bash
source /tmp/.CPprofile.sh
mdsenv

_QRY="cpmiquerybin attr mdsdb network_objects "

${_QRY} "management='true'" -a __name__,primary_management,hosted_by_mds | awk 'gsub("[ \t]+" , "," ,$0) {print}' > /var/tmp/cmastatus.tmp

echo "CMA_NAME, MDS_Server, Primary, Active/Standby"
for _DATA in $(cat /var/tmp/cmastatus.tmp ); do
        _HOST="$(echo ${_DATA} | awk -F"," '{print $3}' )"
        _NAME="$(echo ${_DATA} | awk -F"," '{print $1}' | awk -F"_._._" '{print $1}')"
        _PRIMARY="$(echo ${_DATA} | awk -F"," '{print $2}')"
        _STATUS="$(cprid_util rexec -server ${_HOST} -verbose -rcmd /bin/sh -c "source /etc/profile; mdsenv ${_NAME}; cpmistat -r mg ${_NAME} | grep 'mgActiveStatus' "| awk '{printf "%s",$2}')"

        echo ${_NAME},${_HOST},${_PRIMARY},${_STATUS}
#
done
