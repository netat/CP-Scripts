#!/bin/bash

source /etc/profile.d/CP.sh

SRC="$(printf '%02X' ${1//./ })"
DST="$(printf '%02X' ${3//./ })"
SPRT="$(printf '%08X' ${2})"
DPRT="$(printf '%08X' ${4})"
PROTO="$(printf '%08X' ${5})"



if [[ ($SRC =~ [G-Zg-z] || ${#SRC} -ne 8) || ($DST =~ [G-Zg-z] || ${#DST} -ne 8) ]] || [ "$#" -ne 5 ]; then
    echo "${0##*/} is used to remove connections from the connections table"
    echo
    echo "Usage:"
    echo "${0##*/} SOURCE_IP SOURCE_PORT DESTINATION_IP DESTINATION_PORT IP_PROTOCOL(tcp=6 udp=17)"
    exit
fi

echo "fw tab -t connections -x -e 00000000,$SRC,$SPRT,$DST,$DPRT,$PROTO"
echo "fw tab -t connections -x -e 00000001,$DST,$DPRT,$SRC,$SPRT,$PROTO"

