# HashMake.py
#
# Copyright (c) Cr0w's Place
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

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


PK.replace("-----BEGIN RSA PUBLIC KEY-----", "") #Remove header
PK.replace("-----END RSA PUBLIC KEY-----", "") #Remove footer
FS = CN + ";" + O + ";" + PK + ";" #Final String - concatenation
m = hashlib.md5()
m.update(FS)
print "\nThe string for hashing is %s" %FS
print "\nYour Certificate is: ", m.hexdigest()
print "Run 'python send-OP_RETURN.py <send-address> <send-amount> <certificate>' to send your certificate to the blockchain."
