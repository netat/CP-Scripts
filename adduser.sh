#!/bin/bash
source /etc/profile

#requires MDSM, does not work on SMS
#Will add a user to all cluster members and single gateways in a CMA

adduser() {
    server=$1
    cprid_util rexec -server ${server} -rcmd clish -c "lock database override"
    cprid_util rexec -server ${server} -rcmd clish -c "add user ${USER} uid 0 homedir /home/${USER} "
    cprid_util rexec -verbose -server ${server} -rcmd clish -c "set user ${USER} gid 0 shell /bin/bash"
    cprid_util rexec -server ${server} -rcmd clish -c "set user ${USER} password-hash *"
    cprid_util rexec -server ${server} -rcmd clish -c "add rba user ${USER} roles adminRole" 
    cprid_util rexec -server ${server} -rcmd clish -c "save config"
}
main() {
    hostlist=$(cpmiquerybin attr "" network_objects "type='cluster_member' | type='gateway' " -a __name__,ipaddr | awk '$1 ~ /^fw/ {print $2}')
    for host in $hostlist; do
        (adduser $host ) &
    done
}



while getopts "u:h" opts; do
    case $opt in
        u)
            USER=$OPTARG
            ;;
        h)
            echo "adduser -u username"
            exit
            ;;
    esac
done

main

