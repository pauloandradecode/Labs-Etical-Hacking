import nmap

nm = nmap.PortScanner()
scan = nm.scan('scanme.nmap.org', '22-443', '-sV -sC -O -A -T4')
# print(scan)

# get open ports
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('------------------------------')
        print('Protocol : %s' % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

# get OS
print('\n------------------------------')
print('OS Info')
print('------------------------------')
# validate if OS was found
if nm[host]['osmatch'] == []:
    print('No OS found')
else:
    print('Name: %s' % nm[host]['osmatch'][0]['name'])
    print('Accuracy: %s' % nm[host]['osmatch'][0]['accuracy'])
    print('Type: %s' % nm[host]['osmatch'][0]['osclass'][0]['type'])
    print('Vendor: %s' % nm[host]['osmatch'][0]['osclass'][0]['vendor'])
    print('Os Family: %s' % nm[host]['osmatch'][0]['osclass'][0]['osfamily'])

# get services
for host in nm.all_hosts():
    print('\n------------------------------')
    print('Services')
    print('------------------------------')
    for proto in nm[host].all_protocols():
        print('Protocol : %s' % proto)

        lport = nm[host][proto].keys()
        for port in lport:
            print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
            print('Name : %s' % nm[host][proto][port]['name'])
            print('Product : %s' % nm[host][proto][port]['product'])
            print('Version : %s' % nm[host][proto][port]['version'])
            print('Extra Info : %s' % nm[host][proto][port]['extrainfo'])
            print('Conf : %s' % nm[host][proto][port]['conf'])
            print('CPE : %s' % nm[host][proto][port]['cpe'])
            print('----------')

# save scan results in a csv file
print('\n------------------------------')
print('Saving scan results')
print('------------------------------')
nm.csv()
print('Results saved in nmap.csv')
