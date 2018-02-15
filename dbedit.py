#!/usr/bin/env python

class dbedit:

    def __init__(self, policy_name="##dbedit_policy" ):
        self.policy_name=policy_name
        self.rule_num=0
        self.objects=[]
        self.services=[]

    def check_syntax(self, name):
        reserved_words = (
                    'accept',
                    'all',
                    'All',
                    'and',
                    'any',
                    'Any',
                    'apr',
                    'Apr',
                    'april',
                    'April',
                    'aug',
                    'Aug',
                    'august',
                    'August',
                    'black',
                    'blackboxs',
                    'blue',
                    'broadcasts',
                    'call',
                    'conn',
                    'date',
                    'day',
                    'debug',
                    'dec',
                    'Dec',
                    'december',
                    'December',
                    'deffunc',
                    'define',
                    'delete',
                    'delstate',
                    'direction',
                    'do',
                    'domains',
                    'drop',
                    'dst',
                    'dynamic',
                    'else',
                    'expcall',
                    'expires',
                    'export',
                    'fcall',
                    'feb',
                    'Feb',
                    'february',
                    'February',
                    'firebrick',
                    'foreground',
                    'forest',
                    'format',
                    'fri',
                    'Fri',
                    'friday',
                    'Friday',
                    'from',
                    'fwline',
                    'fwrule',
                    'gateways',
                    'get',
                    'getstate',
                    'gold',
                    'gray',
                    'green',
                    'hashsize',
                    'hold',
                    'host',
                    'hosts',
                    'if',
                    'ifaddr',
                    'ifid',
                    'implies',
                    'in',
                    'inbound',
                    'instate',
                    'interface',
                    'interfaces',
                    'ipsecdata',
                    'ipsecmethods',
                    'is',
                    'jan',
                    'Jan',
                    'january',
                    'January',
                    'jul',
                    'Jul',
                    'july',
                    'July',
                    'jun',
                    'Jun',
                    'june',
                    'June',
                    'kbuf',
                    'keep',
                    'limit',
                    'local',
                    'localhost',
                    'log',
                    'LOG',
                    'logics',
                    'magenta',
                    'mar',
                    'Mar',
                    'march',
                    'March',
                    'may',
                    'May',
                    'mday',
                    'medium',
                    'modify',
                    'mon',
                    'Mon',
                    'monday',
                    'Monday',
                    'month',
                    'mortrap',
                    'navy',
                    'netof',
                    'nets',
                    'nexpires',
                    'not',
                    'nov',
                    'Nov',
                    'november',
                    'November',
                    'oct',
                    'Oct',
                    'october',
                    'October',
                    'or',
                    'orange',
                    'origdport',
                    'origdst',
                    'origsport',
                    'origsrc',
                    'other',
                    'outbound',
                    'packet',
                    'packetid',
                    'packetlen',
                    'pass',
                    'r_arg',
                    'r_call_counter',
                    'r_cdir',
                    'r_cflags',
                    'r_chandler',
                    'r_client_community',
                    'r_client_ifs_grp',
                    'r_community_left',
                    'r_connarg',
                    'r_crule',
                    'r_ctimeout',
                    'r_ctype',
                    'r_curr_feature_id',
                    'r_data_offset',
                    'r_dtmatch',
                    'r_dtmflags',
                    'r_entry',
                    'r_g_offset',
                    'r_ipv6',
                    'r_mapped_ip',
                    'r_mflags',
                    'r_mhandler',
                    'r_mtimeout',
                    'r_oldcdir',
                    'r_pflags',
                    'r_profile_id',
                    'r_ro_client_community',
                    'r_ro_dst_sr',
                    'r_ro_server_community',
                    'r_ro_src_sr',
                    'r_scvres',
                    'r_server_community',
                    'r_server_ifs_grp',
                    'r_service_id',
                    'r_simple_hdrlen',
                    'r_spii_ret',
                    'r_spii_tcpseq',
                    'r_spii_uuid1',
                    'r_spii_uuid2',
                    'r_spii_uuid3',
                    'r_spii_uuid4',
                    'r_str_dport',
                    'r_str_dst',
                    'r_str_ipp',
                    'r_str_sport',
                    'r_str_src',
                    'r_user',
                    'record',
                    'red',
                    'refresh',
                    'reject',
                    'routers',
                    'sat',
                    'Sat',
                    'saturday',
                    'Saturday',
                    'second',
                    'sep',
                    'Sep',
                    'september',
                    'September',
                    'set',
                    'setstate',
                    'skipme',
                    'skippeer',
                    'sr',
                    'src',
                    'static',
                    'sun',
                    'Sun',
                    'sunday',
                    'Sunday',
                    'switchs',
                    'sync',
                    'targets',
                    'thu',
                    'Thu',
                    'thursday',
                    'Thursday',
                    'to',
                    'tod',
                    'tue',
                    'Tue',
                    'tuesday',
                    'Tuesday',
                    'ufp',
                    'vanish',
                    'vars',
                    'wasskipped',
                    'wed',
                    'Wed',
                    'wednesday',
                    'Wednesday',
                    'while',
                    'xlatedport',
                    'xlatedst',
                    'xlatemethod',
                    'xlatesport',
                    'xlatesrc',
                    'xor',
                    'year',
                    'zero',
                    'zero_ip',
                ) #list of reserved words.  sk40179

        reserved_chars = {
                            ' ':'-',
                            '+':'plus',
                            '*':'asterisk', #(asterisk)
                            '(':'_', # (left parenthesis)
                            ')':'_', # (right parenthesis)
                            '{':'_', # (left curly brace)
                            '}':'_', # (right curly brace)
                            '[':'_', # (left square bracket)
                            ']':'_', # (right square bracket)
                            '?':'', # (question mark)
                            '!':'', # (exclamation mark)
                            '#':'hash', # (number/pound sign)
                            '<':'', # (less-than sign)
                            '>':'', # (greater-than sign)
                            '=':'', # (equals sign)
                            ',':'', # (comma)
                            ':':'', # (colon)
                            ';':'', # (semi-colon)
                            "'":'', # (single quote)
                            '"':'', # (double quote)
                            '`':'', # (back quote)
                            '/':'', # (slash)
                            '\\':'', # (backslash)
                            '\t':'', # (horizontal tabulation)
                            '@':'', # (at sign)
                            '$':'', # (dollar sign)
                            '%':'', # (percent sign)
                            '^':'', # (caret)
                            '|':'', # (vertical bar, pipeline)
                            '&':'', # (ampersand)
                            '~':'', # (tilde)
                        } #list of reserved characters sk40179

        #check for restricted characters
        for char in reserved_chars.keys():
            if char in name:
                name=name.replace(char,reserved_chars[char])
            #Note: The "-" (dash) sign is used in INSPECT code as a word separator, and any string that is in the form of: "<characters>-<reserved word>" cannot be used (e.g., the name "something-inbound").
        for word in reserved_words:
            #First check if the reserved word is part of the object name
            if word in name: 
                #Check if the reserved word matches the name exactly.
                if word is name:
                    name = "rename_%s" % name
                else:
                    name.replace('-', '_')
                    name.insert(0,"rename_")
                break

        #Check if first character is a number, if true add the letter n to the beginning of the string.
        if name[0].isdigit() is True:  
            name.insert(0, "n")

        return name


    def mkrule(
                self, 
                src=["Any"], 
                dst=["Any"], 
                service=["Any"], 
                log="True", 
                name="", 
                comments="", 
                disabled="false", 
                action="Accept",
              ):
        ruletext = ""
        if src == []:
            src.append('Any')
        if dst == []:
            dst.append('Any')
        if self.rule_num == 0:
            ruletext += "create policies_collection Dbedit_import\n"
            ruletext += "modify policies_collections Dbedit_import all_internal_modules false\n"
            ruletext += "modify policies_collections Dbedit_import default 0\n"
            ruletext += "update policies_collections Dbedit_import\n"
            ruletext += "create firewall_policy %s\n" % self.policy_name
            ruletext += "modify fw_policies %s default 0\n" % self.policy_name
            ruletext += "modify fw_policies %s collection policies_collections:Dbedit_import\n" % self.policy_name
            
        ruletext += "addelement fw_policies %s rule security_rule\n" % (self.policy_name)     #create new rule
        if comments is not None:
            if "\n" in comments:
                comments = comments.replace("\n", "")
            ruletext += "modify fw_policies %s rule:%s:comments \"%s\"\n" % (
                                                                            self.policy_name, 
                                                                            self.rule_num, 
                                                                            comments
                                                                            )     #modify add comments
        ruletext += "modify fw_policies %s rule:%s:disabled %s\n" % (self.policy_name, self.rule_num, disabled) #disabled status
        if "Any" not in src:
            for source in src:
                ruletext += "addelement fw_policies %s rule:%s:src:'' network_objects:%s\n" %(self.policy_name, self.rule_num, self.check_syntax(source))
        else:
            ruletext += "addelement fw_policies %s rule:%s:src:'' globals:Any\n" %(self.policy_name, self.rule_num)
        ruletext += "modify fw_policies %s rule:%s:src:op ''\n" % (self.policy_name, self.rule_num)
        if "Any" not in dst:
            for dest in dst:
                ruletext += "addelement fw_policies %s rule:%s:dst:'' network_objects:%s\n" %(self.policy_name, self.rule_num, self.check_syntax(dest))
        else:
            ruletext += "addelement fw_policies %s rule:%s:dst:'' globals:Any\n" %(self.policy_name, self.rule_num)
        ruletext += "modify fw_policies %s rule:%s:dst:op ''\n" % (self.policy_name, self.rule_num)

        #Logging status
        if log is "True":
            ruletext += "rmbyindex fw_policies %s rule:%s:track 0\n" % (self.policy_name, self.rule_num)
            ruletext += "addelement fw_policies %s rule:%s:track tracks:Log\n" % (self.policy_name, self.rule_num)
        if action is "Accept":
            ruletext += "addelement fw_policies %s rule:%s:action accept_action:accept\n" % (self.policy_name, self.rule_num)
        else:
            ruletext += "addelement fw_policies %s rule:%s:action drop_action:drop\n" % (self.policy_name, self.rule_num)

        #Add services
        if "Any" not in service:
            for svc in service:
                ruletext += "addelement fw_policies %s rule:%s:services:'' services:%s\n" %(
                                                                                                        self.policy_name, 
                                                                                                        self.rule_num,
                                                                                                        svc,
                                                                                                        )
        else:
            ruletext += "modify fw_policies %s rule:%s:services:'' globals:Any ''\n" % (self.policy_name, self.rule_num)
        ruletext += "addelement fw_policies %s rule:%s:services:op ''\n" % (self.policy_name, self.rule_num)

        self.rule_num+=1
        return ruletext

    def check_service(self, name, proto="6",comment="", dport="" ):
        tcp_services = {
                            'CP_SSL_Network_Extender':'444',
                            'FW1_ica_mgmt_tools':'18265',
                            'MySQL':'3306',
                            'HTTP_and_HTTPS_proxy':'8080',
                            'PostgreSQL':'5432',
                            'SCCP':'2000',
                            'IPSO_Clustering_Mgmt_Protocol':'1111',
                            'FW1':'256',
                            'FW1_log':'257',
                            'FIBMGR':'2010',
                            'FW1_mgmt':'258',
                            'FW1_clntauth_telnet':'259',
                            'FW1_clntauth_http':'900',
                            'FW1_snauth':'261',
                            'FW1_topo':'264',
                            'FW1_key':'265',
                            'FW1_cvp':'18181',
                            'FW1_ufp':'18182',
                            'FW1_amon':'18193',
                            'FW1_omi':'18185',
                            'FW1_omi-sic':'18186',
                            'CP_reporting':'18205',
                            'FW1_CPRID':'18208',
                            'FW1_netso':'19190',
                            'FW1_uaa':'19191',
                            'FW1_pslogon':'18207',
                            'FW1_pslogon_NG':'18231',
                            'FW1_sds_logon':'18232',
                            'FW1_lea':'18184',
                            'FW1_ela':'18187',
                            'CP_rtm':'18202',
                            'FW1_sam':'18183',
                            'FW1_ica_pull':'18210',
                            'FW1_ica_push':'18211',
                            'FW1_ica_services':'18264',
                            'CP_redundant':'18221',
                            'CPMI':'18190',
                            'CPD':'18191',
                            'UserCheck':'18300',
                            'CPD_amon':'18192',
                            'CP_Exnet_PK':'18262',
                            'CP_Exnet_resolve':'18263',
                            'IKE_tcp':'500',
                            'X11':'6000-6063',
                            'OpenWindows':'2000',
                            'nfsd-tcp':'2049',
                            'login':'513',
                            'exec':'512',
                            'shell':'514',
                            #'ssh_version_2':'22',
                            'ssh':'22',
                            'Citrix_ICA':'1494',
                            'telnet':'23',
                            'ftp-port':'21',
                            'ftp-pasv':'21',
                            'ftp-bidir':'21',
                            'ftp':'21',
                            'uucp':'540',
                            'http':'80',
                            'gopher':'70',
                            'wais':'210',
                            'smtp':'25',
                            'pop-2':'109',
                            'pop-3':'110',
                            'nntp':'119',
                            'tcp-high-ports':'">1023"',
                            'netstat':'15',
                            'finger':'79',
                            'ident':'113',
                            'AP-Defender':'2626',
                            'AT-Defender':'2626',
                            'securidprop':'5510',
                            'sqlnet1':'1521',
                            'sqlnet2-1521':'1521',
                            'sqlnet2-1525':'1525',
                            'sqlnet2-1526':'1526',
                            'echo-tcp':'7',
                            'domain-tcp':'53',
                            'Kerberos_v5_TCP':'88',
                            'discard-tcp':'9',
                            'time-tcp':'37',
                            'daytime-tcp':'13',
                            'ntp-tcp':'123',
                            'irc1':'6660-6670',
                            'irc2':'7000',
                            'lotus':'1352',
                            'Real-Audio':'7070',
                            'rtsp':'554',
                            #'ssl_v3':'443',
                            'TACACSplus':'49',
                            'pptp-tcp':'1723',
                            'H323':'1720',
                            'H323_any':'1720',
                            'T.120':'1503',
                            'NCP':'524',
                            'Orbix-1570':'1570',
                            'Orbix-1571':'1571',
                            'OAS-NameServer':'2649',
                            'OAS-ORB':'2651',
                            'ldap':'389',
                            'ldap-ssl':'636',
                            'Entrust-Admin':'710',
                            'Entrust-KeyMgmt':'709',
                            'RainWall_Command':'6374',
                            'StoneBeat-Control':'3002',
                            'StoneBeat-Daemon':'3001',
                            'RealSecure':'2998',
                            'pcANYWHERE-data':'5631',
                            'pcTELECOMMUTE-FileSync':'2299',
                            'https':'443',
                            'imap':'143',
                            'netshow':'1755',
                            'winframe':'1494',
                            'CreativePartnerSrvr':'453',
                            'CreativePartnerClnt':'455',
                            'AOL':'5190',
                            'POP3S':'995',
                            'SMTPS':'465',
                            'EDGE':'981',
                            'ConnectedOnLine':'16384',
                            'FW1_sds_logon_NG':'65524',
                            'MS-SQL-Server':'1433',
                            'MS-SQL-Monitor':'1434',
                            'MSNP':'1863',
                            'MSN_Messenger_File_Transfer':'6891-6900',
                            'Yahoo_Messenger_messages':'5050',
                            'Yahoo_Messenger_Voice_Chat_TCP':'5000-5001',
                            'Yahoo_Messenger_Webcams':'5100',
                            'Direct_Connect_TCP':'411-412',
                            'eDonkey_4661':'4661',
                            'eDonkey_4662':'4662',
                            'GNUtella_rtr_TCP':'6347',
                            'GNUtella_TCP':'6346',
                            'Hotline_client':'5500-5503',
                            'Napster_Client_6600-6699':'6600-6699',
                            'Napster_directory_4444':'4444',
                            'Napster_directory_5555':'5555',
                            'Napster_directory_6666':'6666',
                            'Napster_directory_7777':'7777',
                            'Napster_directory_8888_primary':'8888',
                            'Napster_redirector':'8875',
                            'GoToMyPC':'8200',
                            'iMesh':'5000',
                            'CheckPointExchangeAgent':'18301',
                            'KaZaA':'1214',
                            'Madster':'5025',
                            'RAT':'1097-1098',
                            'Multidropper':'1035',
                            'Kaos':'1212',
                            'SkyDance-T':'4000',
                            'DerSphere':'1000',
                            'Freak2k':'7001',
                            'Jade':'1024',
                            'GateCrasher':'6970',
                            'Kuang2':'17300',
                            'WinHole':'1081',
                            'ICKiller':'1027',
                            'HackaTack_31785':'31785',
                            'HackaTack_31787':'31787',
                            'HackaTack_31788':'31788',
                            'HackaTack_31792':'31792',
                            'UltorsTrojan':'1234',
                            'InCommand':'1029',
                            'Xanadu':'1031',
                            'SubSeven':'27374',
                            'HackaTack_31790':'31790',
                            'Terrortrojan':'3456',
                            'CrackDown':'4444',
                            'lpdw0rm':'515',
                            'TheFlu':'5534',
                            'Shadyshell':'1337',
                            'TransScout':'2004-2005',
                            'Trinoo':'1524',
                            'SocketsdesTroie':'1',
                            'Remote_Storm':'1025',
                            'SubSeven-G':'1243',
                            'Bionet-Setup':'5000',
                            'DaCryptic':'1074',
                            'Mneah':'4666',
                            'Port_6667_trojans':'6667',
                            'DerSphere_II':'2000',
                            'Backage':'411',
                            'DameWare':'6129',
                            'MSNMS':'1863',
                            'sip-tcp':'5060',
                            'sip_any-tcp':'5060',
                            'CP_seam':'18266',
                            'sip-tcp-ipv6':'5060',
                            'sip_any-tcp-ipv6':'5060',
                            'CP_SmartPortal':'4433',
                            'Remote_Desktop_Protocol':'3389',
                            'nbsession':'139',
                            'microsoft-ds':'445',
                            'Squid_NTLM':'3128',
                            'BGP':'179',
                            'IMAP-SSL':'993',
                        } #predefined Check Point Tcp Services
        udp_services = {
                            'UA_CS':'32640',
                            'UA_PHONE':'32512',
                            'dhcp-relay':'67',
                            'VPN1_IPSEC_encapsulation':'2746',
                            'microsoft-ds-udp':'445',
                            'FW1_scv_keep_alive':'18233',
                            'RDP':'259',
                            'FW1_load_agent':'18212',
                            'E2ECP':'18241',
                            'tunnel_test':'18234',
                            'IKE':'500',
                            'FW1_snmp':'260',
                            'snmp':'161',
                            'snmp-trap':'162',
                            'snmp-read':'161',
                            'nfsd':'2049',
                            'tftp':'69',
                            'sip_any':'5060',
                            'sip':'5060',
                            'mgcp_MG':'2427',
                            'mgcp_CA':'2727',
                            'Citrix_ICA_Browsing':'1604',
                            'GTPv0':'3386',
                            'GTPv1-C':'2123',
                            'GTPv1-U':'2152',
                            'rip':'520',
                            'archie':'1525',
                            'udp-high-ports':'">1023"',
                            'who':'513',
                            'syslog':'514',
                            'name':'42',
                            'biff':'512',
                            'bootp':'67',
                            'L2TP':'1701',
                            'dhcp-req-localmodule':'67',
                            'dhcp-rep-localmodule':'68',
                            'securid-udp':'5500',
                            'FreeTel-outgoing-server':'21300',
                            'echo-udp':'7',
                            'domain-udp':'53',
                            'Kerberos_v5_UDP':'88',
                            'kerberos-udp':'750',
                            'discard-udp':'9',
                            'time-udp':'37',
                            'daytime-udp':'13',
                            'ntp-udp':'123',
                            'nbname':'137',
                            'nbdatagram':'138',
                            'interphone':'22555',
                            'RADIUS':'1645',
                            'RADIUS-ACCOUNTING':'1646',
                            'NEW-RADIUS':'1812',
                            'NEW-RADIUS-ACCOUNTING':'1813',
                            'TACACS':'49',
                            'H323_ras':'1719',
                            'H323_ras_only':'1719',
                            'MetaIP-UAT':'5004',
                            'RainWall_Daemon':'6372',
                            'RainWall_Status':'6374',
                            'RainWall_Stop':'6373',
                            'pcANYWHERE-stat':'5632',
                            'CU-SeeMe':'7648-7652',
                            'SWTP_SMS':'9282',
                            'SWTP_Gateway':'9281',
                            'CP_SecureAgent-udp':'19194-19195',
                            'ICQ_locator':'4000',
                            'MSN_Messenger_1863_UDP':'1863',
                            'MSN_Messenger_5190':'5190',
                            'MSN_Messenger_Voice':'6901',
                            'Yahoo_Messenger_Voice_Chat_UDP':'5000-5010',
                            'Direct_Connect_UDP':'411-412',
                            'GNUtella_rtr_UDP':'6347',
                            'GNUtella_UDP':'6346',
                            'Hotline_tracker':'5499',
                            'Blubster':'41170',
                            'RexxRave':'1104',
                            'HackaTack_31789':'31789',
                            'NoBackO':'1201',
                            'HackaTack_31791':'31791',
                            'RIPng':'521',
                            'MS-SQL-Server_UDP':'1433',
                            'MS-SQL-Monitor_UDP':'1434',
                            'WinMX':'6257',
                            'eDonkey_4665':'4665',
                            'MSSQL_resolver':'1434',
                            'wap_wdp_enc':'9202',
                            'wap_wtp_enc':'9203',
                            'wap_wdp':'9200',
                            'wap_wtp':'9201',
                            'IKE_NAT_TRAVERSAL':'4500',
                            'ldap_udp':'389',
                        } #predefined Check Point UDP services
        icmp_services = {
                            'echo-reply':'0',
                            'dest-unreach':'3',
                            'source-quench':'4',
                            'redirect':'5',
                            'echo-request':'8',
                            'time-exceeded':'11',
                            'param-prblm':'12',
                            'timestamp':'13',
                            'timestamp-reply':'14',
                            'info-req':'15',
                            'info-reply':'16',
                            'mask-request':'17',
                            'mask-reply':'18',
                        }

        if proto == '6':  #TCP Service
            if dport in tcp_services.values():
            #Service already exists
                for cpname, port in tcp_services.iteritems():
                    if port == dport:
                        return cpname #Return Check Point Name
            return name

        if proto == '17':  #TCP Service
            if dport in udp_services.values():
            #Service already exists
                for cpname, port in udp_services.iteritems():
                    if port == dport:
                        return cpname #Return Check Point Name
            return name

        if proto == '1':  #TCP Service
            if dport in icmp_services.values():
            #Service already exists
                for cpname, port in icmp_services.iteritems():
                    if port == dport:
                        return cpname #Return Check Point Name
            return name

        
        return name #If Check point service not found, return the object's name


    def mkhost(self, name, addr, comment="" ):
        """ makehost(name, addr, comment """
        text = "create host_plain %s\n" % name
        text += "modify network_objects %s ipaddr %s\n" % (name, addr)
        if comment is not "": text += "modify network_objects %s comments %s\n" % (name, comment)
        return text

    def mknetwork(self, name, addr, subnet, comment=""):
        """makenetwork(name, address, subnetmask, comment)"""
        text = "create network %s\n" % name
        text += "modify network_objects %s ipaddr %s\n" % (name, addr)
        text += "modify network_objects %s netmask %s\n" % (name, subnet)
        if comment is not "": text += "modify network_objects %s comments %s\n" % (name, comment)
        return text

    def mkrange(self, name, start, end, comment=""):
        """makerange is used to create an ip address range
        mkrange(name, start ip address, end ip address, comment)
        """
        text = "create address_range %s\n" % name
        text += "modify network_objects %s ipaddr_first %s\n" % (name, start)
        text += "modify network_objects %s ipaddr_last %s\n" % (name, end)
        if comment is not "": text += "modify network_objects %s comments %s\n" % (name, comment)
        return text

    def mkservice(
                    self, 
                    name, 
                    proto, 
                    port="", 
                    comment="", 
                    color="black", 
                    port_start="", 
                    port_end=""
                    ):
        text = ""
        if proto == "6":
            text += "create tcp_service %s\n" % name
        elif proto == "17":
            text += "create udp_service %s\n" % name
        elif proto == "1": 
            text += "create icmp_service %s\n" % name
        else:
            text += "create other_service %s\n" % name
        if port is not ("", 0):
            text += "modify services %s port %s\n" % (name, port)

        return text
    def mkgroup(
                self,
                name,
                color="black"
                ):
        text = ""
        text += "create network_object_group %s" % name

        return text
    
    def modgroup(
                self,
                name,
                target,
                color="black",
                ):
        text = ""
        text += "addelement network_objects %s '' network_objects:%s" % (name, target)
        return text
    
