#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Cryptography primitives
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.backends import default_backend

# Misc
import argparse
from enum import Enum
from binascii import hexlify, unhexlify

class Script_mode(Enum):
    enddevice = 1
    joinserver = 2
    autonomous = 3

def get_x25519_public_key(public_key_obj):
    return public_key_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def printb(bytes_buf):
    return str(hexlify(bytes_buf), "utf-8")

# Parse the command line to determine in which mode start the script
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--device", action="store_true", help="Start the script in end-device mode. You also need to start a 2nd script in JoinServer mode.")
parser.add_argument("-j", "--joinserver", action="store_true", help="Start the script in JoinServer mode. You also need to start a 2nd script in end-device mode.")
parser.add_argument("-s", "--standalone", action="store_true", help="Start the script in standalone mode (default mode, if no option are set). The script will run autonomously until the end.")
args = parser.parse_args()

if args.device:
    smode = Script_mode.enddevice
    mode = "End-device mode"
elif args.joinserver:
    smode = Script_mode.joinserver
    mode = "JoinServer mode"
else:
    smode = Script_mode.autonomous
    mode = "Autonomous mode"

print("\r\n---------------------------------------------------------")
print("*\t\t", mode, "\t\t\t*")
print("---------------------------------------------------------")

if smode == Script_mode.autonomous:
    print("Autonomous mode is not implemented yet...")
    exit(0)

print("\r\n---------------------------------------------------------")
print("Step 0 - Generate a keyring \r\n")

kpriv = X25519PrivateKey.generate()
kpub = kpriv.public_key()

print("\tNew keyring:")
print("\t\tPRIVATE key:\r\n\t\t> ", "*"*64)
print("\t\tPUBLIC key:\r\n\t\t> ", printb(get_x25519_public_key(kpub)))

print("\r\n---------------------------------------------------------")
print("Step 1 - Exchange public keys\r\n")

print("\tEnter the other public key:")
while True:
    key = input("\t\t> ")
    if len(key) == 64:
        try:
            second_kpub = x25519.X25519PublicKey.from_public_bytes( unhexlify(key) )
            break
        except:
            print("The key format is wrong, check your input.")
    else:
        print("Wrong key length, should be 32 Bytes.")


print("\r\n---------------------------------------------------------")
print("Step 2 - Key agreement based on the key exchange\r\n")

ecdh_res = kpriv.exchange( second_kpub )

print("\tSecret ECDH result:\r\n\t\t", printb(ecdh_res) )

print("\r\n---------------------------------------------------------")
print("Step 3 - Key derivation\r\n")

#TODO: can add ED_EUI + JS_EUI into the salt
salt_appkey = b"AppKey"
salt_nwkkey = b"NwkKey"
salt_otherkey = b"otherKey"

appkey = HKDF( hashes.SHA256(), 16, salt_appkey, None, default_backend() ).derive(ecdh_res)
nwkkey = HKDF( hashes.SHA256(), 16, salt_nwkkey, None, default_backend() ).derive(ecdh_res)
otherkey = HKDF( hashes.SHA256(), 16, salt_otherkey, None, default_backend() ).derive(ecdh_res)

print("\tSecret AppKey:\r\n\t\t", printb(appkey) )
print("\tSecret NwkKey:\r\n\t\t", printb(nwkkey) )
print("\tSecret OtherKey:\r\n\t\t", printb(otherkey) )

print("\r\n---------------------------------------------------------")
