#!/usr/bin/env python3

import pcre

r = pcre.compile(':(?P<f>\S*) \((?P<v>.*)\)$')
r2 = pcre.compile(':\s*(\S+) \(.*$|: \((\S+)$')

def stripper(line):
    line=line.lstrip(' \t\n\r')
    line=line.rstrip(' \t\n\r')
    return(line)


def getobj(name,fh):
    obj = { }
    while 1:
        line = fh.readline()
        line=stripper(line)
#leave this for debugging
        if line is ')':
            return(obj)

        m = r.match(line)
        if m:
            obj[m.group('f')] = m.group('v')
        elif line == ': (ReferenceObject':
            if 'refs' not in obj.keys():
                obj['refs'] = []
            obj['refs'].append(getobj('{}->{}'.format(name,len(obj['refs']) ), fh ))
        else:
#some comments can break the rest of the parser.  Sepcifically '"  so we will read multiple lines until we find a close )
            if ':comments (' in line:   #workaround for strange comments.
                while ')' not in line:
                    line += stripper(fh.readline())
                m = r.match(line)
                if m:
                    obj[m.group('f')] = m.group('v')
                continue


            m=r2.match(line)
            if m:
                if m.group(1) is None:
                    sub=m.group(2)
                else:
                    sub=m.group(1)
            else:
                sub='None'
            obj[sub] = getobj('{}->{}'.format(name,sub), fh)

def fixobjects(obj):
    data = {
            'uid' : obj['AdminInfo']['chkpf_uid'].strip('}{"'),
            'ClassName' : obj['AdminInfo']['ClassName'],
            'color' : obj['color'],
            'comments' : obj['comments'],
            'type' : obj['type'],
           # 'global_level' : obj['global_level'],
            }
    if data['ClassName'] in ['gateway_cluster','gateway_ckp' ] and 'interfaces' in obj.keys():
        data['interfaces'] = {}
        for iface in obj['interfaces'].keys():
            data['interfaces'][ obj['interfaces'][iface]['officialname'] ] = {
                            'ipaddr' : obj['interfaces'][iface]['ipaddr'],
                            'netmask' : obj['interfaces'][iface]['netmask'],
                            'ipaddr6' :obj['interfaces'][iface]['ipaddr6'],
                            'netmask6': obj['interfaces'][iface]['netmask6'],
                            'antispoof': obj['interfaces'][iface]['antispoof'],
                            'access': obj['interfaces'][iface]['netaccess']['access'],
                            'allowed': obj['interfaces'][iface]['netaccess']['allowed'],
                            }
        return(data)
    if data['ClassName'] == 'network_object_group':
        data['members'] = []
        if 'refs' in obj.keys():
            for member in obj['refs']:
                data['members'].append(member['Name'])
    if data['ClassName'] == 'host_plain':
        data['ipaddr'] = obj['ipaddr']
    if data['ClassName'] == 'network':
        data['ipaddr'] = obj['ipaddr']
        data['netmask'] = obj['netmask']
    if data['ClassName'] == 'address_range':
        data['ipaddr_first'] = obj['ipaddr_first']
        data['ipaddr_last'] = obj['ipaddr_last']
    if 'global_level' in obj['AdminInfo']:
        data['global_level'] = True
    #add support for automatic nat
    if 'add_adtr_rule' in obj.keys() :
        if obj['add_adtr_rule'] == 'true':
            data['add_adtr_rule']= obj['add_adtr_rule']
            data['nat_method'] = obj['netobj_adtr_method']
            data['nat_ip']=obj['valid_ipaddr']
            data['nat_hidebehind']=obj['the_firewalling_obj']['Name']
    return(data)
        
    #return(obj)
    


def odict(objectsfile):

    headers = ['network_objects', 'services']
    objects50 = {}
    for h in headers:
        objects50[h] = {}

    with open(objectsfile, 'r', encoding='cp1252') as fh:
        for line in fh:
            line = line.rstrip(' \t\r\n')
            line = line.lstrip(' \t\r\n')
            for h in headers: 
               if ':{} ('.format(h) == line:
                   while line is not ')':
                       line=fh.readline()
                       line = line.rstrip(' \t\r\n')
                       line = line.lstrip(' \t\r\n')
                       if line == ')':
                           break
                       myobj = line.split()[1].lstrip('(')
                       #print('getting obj {}'.format(myobj))
                       objects50[h][myobj] = fixobjects(getobj(myobj,fh))
                    #   print('got obj')

    return(objects50)

def fixrule(rule):
    data = {
            'comments' : rule['comments'],
            'disabled' : rule['disabled'],
            'name'     : rule['name'],
            'src'      : [],
            'dst'      : [],
            'services' : [],
            'action'   : rule['action'][list(rule['action'].keys())[0]]['type'],
            }

    if 'global_level' in rule['AdminInfo'].keys():
        data['global'] = True


    for t in ['src','dst','services']:
#Workaround for userobjects.
        if 'refs' not in rule[t].keys():
            rule[t]['refs'] = []
        for i in rule[t]['refs']:
            #rule[t].append(i)
            data[t].append(i['Name'])
    return(data)


def rdict(rulebasefile='rulebases_5_0.fws'):
    policy = None
    rules = { }
    rbregex = pcre.compile(':rule-base \("(?P<policy>##\S+)"$')
    with open(rulebasefile, 'r') as fh:
        for line in fh:
            line = stripper(line)
            m = rbregex.match(line)
            if m:
                policy = m.group('policy')
                rules[policy]={
                            'rules' : [],
                            'nat' : [],
                    }
            if not policy: #this is needed to prevent object reference errors
                continue
            if line == ':rule (':
                rule = fixrule(getobj(
                                    len(rules[policy]['rules']),
                                    fh
                                    )
                               )

                rules[policy]['rules'].append(rule)

        return(rules)




if __name__ == '__main__':
    import pprint
    pp = pprint.PrettyPrinter(indent=2)
    #x = rdict()
    #with open('rules', 'w') as fh:
        #pprint.pprint(x,fh)
        
    x = odict('objects_5_0.C')
    for h in ['network_objects','services']:
        with open(h,'w') as fh:
            pprint.pprint(x[h],fh)
