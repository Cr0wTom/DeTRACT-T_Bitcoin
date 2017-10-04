#!/usr/bin/python

import sys, string, hashlib
from Crypto.PublicKey import RSA
from OP_RETURN import *

CN = raw_input("Which is the primary Host Name of your website (Common Name - CN)?") #Common Name
O = raw_input("Which is the Organizations name?") #Organization
O2 = O.replace(" ", "_") #Replace the spaces of the Organization with underscores
ans = raw_input("Do you have a key pair? [Y]es [N]o, default: [Y]")
if ans == "Y" or ans == "y" or ans == "" or ans == " ":
    PK = raw_input("Which is your public key?") #Public Key of the owner
else:
    #pip install pycryptodome
    print "Public/Private key pair creation:" #RSA Public/Private key pair creation with PyCryptodome
    print "Warning: This is a pseudo-random generation."
    print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation."

    secret_code = raw_input("Give an unguessable passphrase: ")
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")

    file_out = open("rsa_key.bin", "wb") #Save the keys to the rsa_key.bin
    file_out.write(encrypted_key)

    print key.publickey().exportKey()
    PK = key.publickey().exportKey()


PK2 = PK.replace("-----BEGIN RSA PUBLIC KEY-----", "") #Remove header
PK3 = PK2.replace("-----END RSA PUBLIC KEY-----", "") #Remove footer
FS = CN + ";" + O2 + ";" + PK3 + ";" #Final String - concatenation
m = hashlib.sha256()
m.update(FS)
print "\nThe string for hashing is %s" %FS
print "\nYour Certificate is: ", m.hexdigest()
ans2 = raw_input("Do you want to send your certificate to the blockchain? [Y]es [N]o, default: [Y]")
if ans2 == "Y" or ans2 == "y" or ans2 == "" or ans2 == " ":
    send_address = raw_input("Give your bitcoin address: ") # Transaction to the same bitcoin address
    send_amount = 0.00009 # Minimum ammount of bitcoin transaction fee
    metadata = m.hexdigest() # metadata equals the SHA256 hash that was previously denerated
    metadata_from_hex=OP_RETURN_hex_to_bin(metadata)
    if metadata_from_hex is not None:
	       metadata=metadata_from_hex

    result=OP_RETURN_send(send_address, float(send_amount), metadata)
    if 'error' in result:
	       print('Error: '+result['error'])
    else:
	       print('TxID: '+result['txid']+'\nWait a few seconds then check on: http://coinsecrets.org/')
else:
    sys.exit()
