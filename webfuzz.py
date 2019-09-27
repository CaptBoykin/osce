#!/usr/bin/env python3

from collections import OrderedDict
from time import sleep
from struct import pack
from datetime import datetime
import socket
import sys

def p(x):
    return pack('<I',x)

rhost='192.168.102.183'
rport=7510
hdr_host=rhost+":"+str(rport)
hdr_url='/topology/homeBaseView'
hdr_proto="HTTP"
hdr_verb="GET"
hdr_useragent="Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.14);"
hdr_contenttype="text/html"
hdr_etag="asdf"
hdr_ref= "%s://%s/" % (hdr_proto,hdr_host)
hdr_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
hdr_date = str(datetime.now())
hdr_contentlength = 1048580
fuzz_size = 7500
fuzz_step = 500
fuzz_start = 0
fuzz_char = 'A'
skip_list = []

for k,v in enumerate(sys.argv):
    if v in ['-size']:
        fuzz_size = int(sys.argv[k+1])
    if v in ['-start']:
        fuzz_start = int(sys.argv[k+1])
    if v in ['-step']:
        fuzz_step = int(sys.argv[k+1])
    if v in ['-char']:
        fuzz_char = sys.argv[k+1]
    if v in ['-r','--rhost']:
        rhost = sys.argv[k+1]
    if v in ['-p','--rport']:
        rport = sys.argv[k+1]
    if v in ['-u','--url']:
        hdr_url = sys.argv[k+1]
    if v in ['-verb']:
        hdr_verb = sys.argv[k+1]
    if v in ['-proto']:
        hdr_proto = sys.argv[k+1]
    if v in ['--skip']:
        index = {"v":"VERB","u":"URL",
                "h":"HOST","ua":"USER-AGENT",
                "ct":"CONTENT-TYPE","r":"REFERER",
                "e":"ETAG","d":"DATE","a":"ACCEPT",
                "cl":"CONTENT-LENGTH"}

        tmp = sys.argv[k+1].split(':')
        for tag in tmp:
            skip_list.append(index[tag])

pos_dict = { 'hdr_verb':hdr_verb, 'hdr_url':hdr_url, 
             'hdr_host':hdr_host, 'hdr_useragent':hdr_useragent, 
             'hdr_contenttype':hdr_contenttype, 'hdr_ref':hdr_ref,
             'hdr_etag':hdr_etag, 'hdr_date':hdr_date, 
             'hdr_accept':hdr_accept, 'hdr_contentlength':hdr_contentlength}

pos_list_labels = ['VERB','URL','HOST',
                    'USER-AGENT','CONTENT-TYPE','REFERFER',
                    'ETAG','DATE', 'ACCEPT','CONTENT-LENGTH']

for k,v in enumerate(pos_dict):

    for ii in range(fuzz_start,fuzz_size,fuzz_step):

        # Unlike the other header aspects...we cannot
        # skip these and there must always be a value
        if 'VERB' in skip_list:
            if v == 'hdr_verb':
                continue
        if 'URL' in skip_list:
            if v == 'hdr_url':
                continue
        if 'HOST' in skip_list:
            if v == 'hdr_host':
                continue

        default = pos_dict[v]
        pos_dict[v] = fuzz_char * ii

        print("[*] Trying position [%s] size [%s]" % (pos_list_labels[k],str(ii)))
        input("    >>>> PRESS ENTER TO SEND <<<< ")
        
        req = ""
        req +=  "%s /%s HTTP/1.1\r\n" % (pos_dict['hdr_verb'],pos_dict['hdr_url'])
        req +=  "Host: %s\r\n" % (pos_dict['hdr_host'])
        
        if 'USER-AGENT' not in skip_list:
            req += "User-Agent: %s\r\n\r\n" % (pos_dict['hdr_useragent'])
        if 'CONTENT-TYPE' not in skip_list:
            req += "Content-Type: %s\r\n" % (pos_dict['hdr_contenttype'])
        if 'REFERER' not in skip_list:
            req += "Referer: %s\r\n" % (pos_dict['hdr_referer'])
        if 'ETAG' not in skip_list:
            req += "Etag: %s\r\n" % (pos_dict['hdr_etag'])
        if 'DATE' not in skip_list:
            req += "Date: %s\r\n" % (pos_dict['hdr_date'])
        if 'ACCEPT' not in skip_list:
            req += "Accept: %s\r\n" % (pos_dict['hdr_accept'])
        if pos_dict['hdr_verb'] in ['PUT','POST']:
            if 'CONTENT-LENGTH' not in skip_list:
                req += "Content-Length %s\r\n" % (len(req))
        else:
                req += "Content-Length: %s\r\n" % (str(pos_dict['hdr_contentlength']))

        sockfd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sockfd.connect((rhost,rport))
        sockfd.send(req.encode())
        pos_dict[v] = default
        sleep(0.5)
