#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap")
ssid = "SWI"

for packet in wpa :

    # Le premier paquet avec le type, le sous-type à 0 -> Association Request, contient toutes les infos nécessaires
    if (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x0) and (packet.info.decode('ascii') == ssid):
        # Adresse MAC de l'AP
        APmac = a2b_hex((packet.addr1).replace(":", ""))
        print(APmac)
        # Adresse de la station
        Clientmac = a2b_hex((packet.addr2).replace(":", ""))
        print(Clientmac)
        # SSID du réseau
        print(ssid)
        break


for packet in wpa :
    if (packet.type == 0x2) and (packet.subtype == 0x0) and (packet.proto == 0x0) :
            #and (APmac == a2b_hex(packet.addr1.replace(":", ""))) and (Clientmac == a2b_hex((packet.addr2).replace(":", ""))) :
        ANonce = packet.load[13:45]
        print("ANonce : ", ANonce)
        break

first_packet = True

for packet in wpa :
    if first_packet and (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        #and (APmac == packet.addr1.replace(":", "")) and (Clientmac == (packet.addr2).replace(":", "")) :
        SNonce = Dot11Elt(packet).load[65:97]
        print("SNonce : ", SNonce)

        first_packet = False


    elif (packet.type == 0x0) and (packet.subtype == 0x0) and (packet.proto == 0x1) :
        #and (APmac == packet.addr1.replace(":", "")) and (Clientmac == (packet.addr2).replace(":", "")) :
        mic_to_test = Dot11Elt(packet).load[129:-2].hex()
        print("Mic_to_test : ", mic_to_test)
        break

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
#sid        = "SWI"
#APmac       = a2b_hex("cebcc8fdcab7")
#Clientmac   = a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
#ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
#SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
#mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") #cf "Quelques détails importants" dans la donnée

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
