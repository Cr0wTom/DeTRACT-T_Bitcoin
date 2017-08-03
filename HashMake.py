#!/usr/bin/python
import hashlib
import string
from Crypto.PublicKey import RSA

CN = raw_input("Which is the primary Host Name of your website (Common Name - CN)?") #Common Name
O = raw_input("Which is the Organizations name?") #Organization
O.replace(" ", "_") #Replace the spaces of the Organization with underscores
ans = raw_input("Do you have a key pair? [Y]es [N]o, default: [Y]")
if ans == "Y" or ans == "y" or ans == "" or ans == " ":
    PK = raw_input("Which is your publick key?") #Public Key of the owner
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


#PK.replace("-----BEGIN RSA PUBLIC KEY-----", "") #Remove header
#PK.replace("-----END RSA PUBLIC KEY-----", "") #Remove footer
FS = CN + ";" + O + ";" + PK + ";" #Final String - concatenation
m = hashlib.sha256()
m.update(FS)
print "\nThe string for hashing is %s" %FS
print "\nYour Certificate is: ", m.hexdigest()
print "Run 'python send-OP_RETURN.py <send-address> <send-amount> <certificate>' to send your certificate to the blockchain."
