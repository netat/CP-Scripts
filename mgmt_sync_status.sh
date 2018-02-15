#!/bin/bash

. /etc/profile.d/CP.sh

#needs to be cleaned up, but this will print the primary
for i in $($MDSVERUTIL AllCMAs); do 
    mdsenv $i; 
    echo $i ; 
    cpprod_util FwGetParam Primary; 
done

