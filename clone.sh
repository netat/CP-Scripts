#!/bin/bash

#I am not sourcing CP.sh  the mdsenv should be set before executing
#source /etc/profile.d/CP.sh

usage() {
      echo
      echo "USAGE: "
      echo "$0 [ -o ORIGINAL ] [ -n NEW] [ -d ] " 
      echo 
      echo -e "\e[31;1;5m"
      echo "*** This script must be run within the context of the CMA ***"
      echo -e "\trun: mdsenv CMANAME"
      echo -e "\tbefore running $0"
      echo -e "\e[0m"
      echo
      echo "ORIGINAL is the existing object name to be copied"
      echo "NEW is the NEW object name to be added"
      echo "-d use used to print additional debug information"
      echo -e "\n\n"
      exit 0

}

duplicator() {
    #this will update all policies based on the rulebases_5.0.fws
    #run on a per policy basis, pull policy with the command:
    #cpmiquerybin object "" fw_policies ""
    awk -v host=${OLDOBJ} -v newhost=${NEWOBJ} 'BEGIN {
            numtab = 0
            no = 0
            rule = -1
            rulebase=""
    }

    numtab == 0 {
# uncomment to enable creation of NAT rules
        #if(natrule > 0){
            ###increment the rule counter for a new rule
            #for(var=0;var<=arri;var++){
                #gsub("_XXXXXX",natrule,natarr[var])
                #printf natarr[var]
                #if(natarr[var] ~ /:disabled true/){
                    #natrule++
                #}
            #}
            #delete natarr
        #}
            #natarr[0]=""
            rule=-1
            natrule=-1
            donat=0
            rulebase=$1
            gsub("[)(\"]","",rulebase)
    }

    /:rule \(/ && numtab==1  {
            unset dorule;
            unset donat;
    }
    /:rule_adtr \(/ && numtab == 1 {
        unset dorule;
        unset donat;
        natcomments = ""
    }
#only do stuff on security rules
    numtab == 2 && admininfo == 1  { admininfo = 0 }
    numtab == 2 &&  /:AdminInfo /   { admininfo=1   }
    admininfo == 1 && numtab == 3 && /:ClassName/ {
        gsub(/[()]/,"",$NF);
        if ("security_rule" ==  $NF) 
            {
                rule+=1;
                dorule=1
            }
        else if ("security_header_rule" == $NF)
            {
                rule+=1;
                dorule=0
            }
        else if ("address_translation_rule" == $NF)
            {
                donat = 1
                dorule = 0 
                natrule++
            }
        else if ("nat_header_rule" == $NF)
            {
                dorule = 0
                donat = 0
                natrule++
            }
        else 
            {
                dorule=0
            }
    }
    rulebase == "##Global_Rules_Container" {dorule=0;donat=0}

    ####Nat Section####
        donat == 1 && numtab == 1 { 
            if(pnat == 1 ) {
                #Create New Nat Rule
                arri++
                natarr[arri]=sprintf("addelement fw_policies %s rule_adtr address_translation_rule\n",rulebase)
                arri++

                #Add Comments
                natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:comments \47%s\47\n",rulebase,natcomments)
                arri++

                #Add Source Address
                sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:src_adtr network_objects:%s\n",rulebase,natsrc)
                if(natsrc != "Any"){
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:src_adtr network_objects:%s\n",rulebase,natsrc)
                    arri++
                    }
                else {
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:src_adtr globals:Any\n",rulebase)
                    arri++
                }

                #Add Destination Address
                if(natdst != "Any"){
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:dst_adtr network_objects:%s\n",rulebase,natdst)
                    arri++
                }
                else {
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:dst_adtr globals:Any\n",rulebase)
                    arri++
                }

                #Add Service
                if(natsvc != "Any"){
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:services_adtr services:%s\n",rulebase,natsvc)
                    arri++
                }
                else {
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:services_adtr globals:Any\n",rulebase)
                    arri++
                }

                #Add translated srouce
                natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:src_adtr_translated %s\n",rulebase,natsrctype)
                arri++
                if(natsrct != "Any"){
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:src_adtr_translated:\47\47 network_objects:%s\n",rulebase,natsrct)
                    arri++
                }
                else {
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:src_adtr_translated:\47\47 globals:Any\n",rulebase)
                    arri++
                }

                #Add translated Destination
                natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:dst_adtr_translated %s\n",rulebase,natdsttype)
                arri++
                if(natdstt != "Any"){
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:dst_adtr_translated:\47\47 network_objects:%s\n",rulebase,natdstt)
                    arri++
                }
                else {
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:dst_adtr_translated:\47\47 globals:Any\n",rulebase)
                    arri++
                }

                #Add Translated service
                natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:services_adtr_translated service_translate\n",rulebase)
                arri++
                if(natsvct != "Any"){
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:services_adtr_translated:\47\47 services:%s\n",rulebase,natsvct)
                    arri++
                }
                else {
                    natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:services_adtr_translated:\47\47 globals:Any\n",rulebase)
                    arri++
                }
                #Add Install Target 
                if(natinstallt != "Any"){
                    natarr[arri]=sprintf("addelement fw_policies %s rule_adtr:_XXXXXX:install network_objects:%s\n",rulebase,natinstallt)
                    arri++
                }
                #Add name if there is one
                #if(length(natname) > 0){
                    #natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:name \47%s\47\n",rulebase,natname)
                    #arri++
                #}
                #Disable the rule
                #This part must go last other parts of the script depend on it!!!!!
                natarr[arri]=sprintf("modify fw_policies %s rule_adtr:_XXXXXX:disabled true\n",rulebase)
                arri++
            }
    #reset nat variables
            unset natsrc
            unset natdst
            unset natsvc
            unset natsrct
            unset natdstt
            unset natsvct
            unset natsrctype
            unset natdsttype
            unset natcomments
            unset natname
            unset natinstallt
            pnat = 0
    }

    #Cludgy section that determines which field I am in
        donat == 1 && numtab == 2 && donsrc == 1            { donsrc = 0}
        donat == 1 && numtab == 2 && /:src_adtr \(/         { donsrc = 1 } 
        donat == 1 && numtab == 2 && dondst == 1            { dondst = 0}
        donat == 1 && numtab == 2 && /:dst_adtr \(/         { dondst = 1 } 
        donat == 1 && numtab == 2 && donsvc == 1            { donsvc = 0}
        donat == 1 && numtab == 2 && /:services_adtr \(/    { donsvc = 1 } 
        donat == 1 && numtab == 2 && donsrcadtr == 1        { donsrcadtr = 0}
        donat == 1 && numtab == 2 && /:src_adtr_translated \(/    { donsrcadtr = 1 } 
        donat == 1 && numtab == 2 && dondstadtr == 1        { dondstadtr = 0}
        donat == 1 && numtab == 2 && /:dst_adtr_translated \(/    { dondstadtr = 1 } 
        donat == 1 && numtab == 2 && donsvcadtr == 1        { donsvcadtr = 0}
        donat == 1 && numtab == 2 && /:services_adtr_translated \(/    { donsvcadtr = 1 } 
        donat == 1 && numtab == 2 && doninst ==1            { doninst = 0 }
        donat == 1 && numtab == 2 && /:install \(/          { doninst = 1 }

        donat == 1 && /:comments / {
                gsub(/[()]/,"",$0);
                for(i=2;i<=NF;i++){
                    natcomments=natcomments" "$i
                }
            }
        donat ==  1 && /:name / {
                gsub(/[()]/,"",$0);
                for(i=2;i<=NF;i++){
                    natname=natname" "$i
                }
            }


        dondst == 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natdst = $2
                if (host  == $2) {
                    natdst = newhost
                    pnat=1
                 }
             }
        donsrc == 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natsrc = $2
                if (host == $2 ) {
                    natsrc = newhost
                    pnat=1
                 }
             }
        donsvc == 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natsvc = $2
                if (host == $2) {
                    pnat=1
                 }
             }
        donsrcadtr== 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natsrct = $2
                if (host == $2) {
                    natsrct = newhost
                    pnat=1
                 }
             }
        donsrcadtr == 1 && /:adtr_method / {
                gsub(/[()]/,"",$2);
                if($2 == "adtr_method_static") 
                    $2 = "translate_static" 
                else
                    $2 = "translate_hide"
                natsrctype = $2
            }
        dondstadtr == 1 && /:adtr_method / {
                gsub(/[()]/,"",$2);
                if($2 == "adtr_method_static") 
                    $2 = "translate_static" 
                else
                    $2 = "translate_hide"
                natdsttype = $2
            }
        dondstadtr== 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natdstt = $2
                if (host == $2) {
                    natdstt = newhost
                    pnat=1
                 }
             }
        donsvcadtr== 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natsvct = $2
             }
        doninst == 1 && /:Name/  {
                gsub(/[()]/,"",$2);
                natinstallt = $2
                if (host == $2) {
                    natinstallt = newhost
                    printf "addelement fw_policies %s rule_adtr:%s:install network_objects:%s\n",rulebase,natrule,natinstallt
                 }
             }
    ####END NAT SECTION####

#filter for destination
    numtab == 2 && dodst == 1   { dodst = 0}
    numtab == 2 && /:dst \(/    { dodst = 1} 
    dodst == 1 && numtab == 4 &&  /:Name \(/  {
            gsub(/[()]/,"",$NF);
            if (host == $NF) {
                p=1
                indst=1
             }
         }    

    numtab == 2 && dosrc == 1   { dosrc = 0}
    numtab == 2 && /:src \(/    { dosrc = 1} 
    dosrc == 1 && numtab == 4 &&  /:Name \(/  {
            gsub(/[()]/,"",$NF);
            if (host == $NF) {
                p=1
                insrc=1
             }
         }    
         
    numtab == 2 && doinstall == 1   { doinstall = 0}
    numtab == 2 && /:install \(/    { doinstall = 1} 
    doinstall == 1 && numtab == 4 &&  /:Name \(/  {
            gsub(/[()]/,"",$NF);
            if (host == $NF) {
                p=1
                ininstall=1
             }
         }    

    /\(/ { numtab++}
    /\)/ { numtab--}
    numtab == 1 && p==1 {
        if (insrc == 1){
#        printf "rule: %s addsrc\n", rule
            printf "addelement fw_policies %s rule:%s:src:\47\47 network_objects:%s\n",rulebase, rule,newhost 
        }
        if (indst == 1){
            printf "addelement fw_policies %s rule:%s:dst:\47\47 network_objects:%s\n",rulebase, rule,newhost 
        }
        if (ininstall == 1){
            printf "addelement fw_policies %s rule:%s:install:\47\47 network_objects:%s\n",rulebase, rule,newhost 
        }
        p=0
        insrc=0
        indst=0
    }
        
    END {
        # uncomment to enable creation of nat rules
        #if(natrule > 0){
            ###increment the rule counter for a new rule
            #for(var=0;var<=arri;var++){
                #gsub("_XXXXXX",natrule,natarr[var])
                #printf natarr[var]
                #if(natarr[var] ~ /:disabled true/){
                    #natrule++
                #}
            #}
            #delete natarr
        print "update_all"
    }'

}

main() {
    [ ${OLDOBJ} ] || usage
    [ ${NEWOBJ} ] || usage

    if [ -f "${NEWOBJ}.dbedit" ]; then
        mv ${NEWOBJ}.dbedit ${NEWOBJ}.dbedit.old.$(date +"%s")
    fi

    cpmiquerybin object "" fw_policies "" | duplicator > ${NEWOBJ}.dbedit
    if [ $? -eq 0 ]; then
        echo -e "${NEWOBJ}.dbedit has been created."
        echo -e "to make the changes please run:"
        echo -e "\t dbedit -local -f ${NEWOBJ}.dbedit"
    fi
}



while getopts "o:n:hd" opt; do
  case $opt in
    o)
        OLDOBJ=$OPTARG
        ;;
    n)
        NEWOBJ=$OPTARG
        ;;
    h)
        usage >&2
        ;;
    d)
        DEBUG=1
        ;;
  esac
done

main
