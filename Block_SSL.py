#!/usr/bin/python

import sys
import string
import hashlib
import os
import random
import struct
import getpass
import datetime
from datetime import timedelta
from Crypto.Cipher import AES
from pybitcoin import BitcoinPrivateKey, make_op_return_tx, BlockchainInfoClient, send_to_address
from OpenSSL import crypto, SSL
from ecdsa import SigningKey
#For pybitcoin download and install from:
#https://github.com/blockstack/pybitcoin.git


def identityCreation():
    print "\nIdentity Creation Script - Block SSL\n"
    ex = raw_input("Do you already own a BitCoin address that you want to use? [Y]es [N]o, default: [Y]")
    if ex == "Y" or ex == "y" or ex == "" or ex == " ":
        gen_priv = raw_input("Which is your private key? (in hexadecimal format)\n")  #Private Key of the owner
        gen_priv = BitcoinPrivateKey(gen_priv)
        print "Saving to Generation_Private.pem file..."
        open("Generation_Private.pem", "w").write(gen_priv.to_pem())  #Saving to file
        print "Generating \"Generation\" Public Key..."
        gen_pub = gen_priv.public_key()  #Generate the "Generation" public key from gen_priv
        print "Saving to Generation_Public.pem file..."
        open("Generation_Public.pem", "w").write(gen_pub.to_pem())  #Saving to file
        print "Public/Private key pair creation:"
        print "Warning: This is a pseudo-random generation."
        print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation."

    else:
        print "Public/Private key pair creation:"
        print "Warning: This is a pseudo-random generation."
        print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation.\n"

        print "Generating \"Generation\" Private Key..."
        gen_priv = BitcoinPrivateKey()  #Generate the "Generation" private key
        print "Saving to Generation_Private.pem file..."
        open("Generation_Private.pem", "w").write(gen_priv.to_pem())  #Saving to file
        print "Generating \"Generation\" Public Key..."
        gen_pub = gen_priv.public_key()  #Generate the "Generation" public key from gen_priv
        print "Saving to Generation_Public.pem file..."
        open("Generation_Public.pem", "w").write(gen_pub.to_pem())  #Saving to file

    print "Generating \"Certificate\" Private Key..."
    cert_priv = BitcoinPrivateKey()  #Generate the "Certificate" private key
    print "Saving to Certificate_Private.pem file..."
    open("Certificate_Private.pem", "w").write(cert_priv.to_pem())  #Saving to file
    print "Generating \"Certificate\" Public Key..."
    cert_pub = cert_priv.public_key()  #Generate the "Certificate" public key from cert_priv
    print "Saving to Certificate_Public.pem file..."
    open("Certificate_Public.pem", "w").write(cert_pub.to_pem())  #Saving to file

    print "Generating \"Revocation\" Private Key..."
    rev_priv = BitcoinPrivateKey()  #Generate the "Revocation" private key
    print "Saving to Revocation_Private.pem file..."
    open("Revocation_Private.pem", "w").write(rev_priv.to_pem())  #Saving to file
    print "Generating \"Revocation\" Public Key..."
    rev_pub = rev_priv.public_key()  #Generate the "Revocation" public key from rev_priv
    print "Saving to Revocation_Public.pem file..."
    open("Revocation_Public.pem", "w").write(rev_pub.to_pem())  #Saving to file

    open("Gen_Address.txt", "w").write(gen_pub.address()) #save the addresses to make the hash later
    open("Rev_Address.txt", "w").write(rev_pub.address())
    open("Cert_Address.txt", "w").write(cert_pub.address()) #save it for the transaction
    print "\nYour addresses are:"
    print "\nGeneration Address: ", gen_pub.address()
    print "\nCertificate Address: ", cert_pub.address()
    print "\nRevocation Address: ", rev_pub.address()
    print "\nWarning: Please keep your Revocation address secret!"
    ans = raw_input("Do you want to encrypt your private key files? [Y]es [N]o, default: [Y]")
    if ans == "Y" or ans == "y" or ans == "" or ans == " ":
        password = getpass.getpass("Give a strong password: ")  #Ask for encryption password
        key = hashlib.sha256(password).digest()
        encrypt_file(key, "Generation_Private.pem")
        os.remove("Generation_Private.pem")
        encrypt_file(key, "Certificate_Private.pem")
        os.remove("Certificate_Private.pem")
        encrypt_file(key, "Revocation_Private.pem")
        os.remove("Revocation_Private.pem")
        sys.exit()
    else:
        sys.exit()


def identityUpdate():
    sys.exit()


def identityCheck():
    sys.exit()


def certificateCreation():
    print "\nCertificate Creation Script - Block SSL\n"
    # create a key pair
    print "Creating a new key pair:"
    print "Warning: This is a pseudo-random generation.\n"
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 1024)

    # create a self-signed cert
    cert = crypto.X509()
    country = raw_input("Country Name (2 letter code): ")
    cert.get_subject().C = country
    state = raw_input("State or Province Name (full name): ")
    cert.get_subject().ST = state
    local = raw_input("Locality Name (eg, city): ")
    cert.get_subject().L = local
    org = raw_input("Organization Name (eg, company): ")
    cert.get_subject().O = org
    orgu = raw_input("Organizational Unit Name (eg, section): ")
    cert.get_subject().OU = orgu
    cn = raw_input("Common Name (eg, fully qualified host name): ")
    cert.get_subject().CN = cn
    email = raw_input("email Address: ")
    cert.get_subject().emailAddress = email
    cert.set_serial_number(1000) #todo - take the last number from merkle tree
    cert.gmtime_adj_notBefore(0)
    now = datetime.datetime.now() #setting the time right now
    tr = 0
    while tr == 0:
        an = int(raw_input("How long do you need the certificate to last in days? (maximum: 365)\n"))
        if an < 366 and an > 0:
            cert.gmtime_adj_notAfter(60*60*24*an)
            tr += 1
        else:
            print "Please give a number smaller than 366.\n"
            tr = 0
    diff = datetime.timedelta(an)
    future = now + diff
    print future.strftime("\nYour certificate expires on %m/%d/%Y") #print the expiration date
    print "\nAdding the GE and RV signatures to the issuer field..."
    message_gen = open("Gen_Address.txt", "rb").read()
    m1 = hashlib.sha256()
    m1.update(message_gen)
    m1 = m1.hexdigest()
    message_rev = open("Rev_Address.txt", "rb").read()
    m2 = hashlib.sha256()
    m2.update(message_rev)
    m2 = m2.hexdigest()
    cert.get_issuer().CN = m1 #Generation address at the CN issuer field
    cert.get_issuer().O = m2 #Revocation address at the O issuer field
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    #todo - change the lame file names
    open("certificate.crt", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open("keys.key", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print "\nCertificate created in file: certificate.crt"
    print "\nKeys saved in file: keys.key\n"

    ans2 = raw_input("Do you want to send your certificate to the blockchain? [Y]es [N]o, default: [Y]")
    if ans2 == "Y" or ans2 == "y" or ans2 == "" or ans2 == " ":
        #Hashing of the certificate
        f = open("certificate.crt", "rb") #read file in binary mode
        fr = f.read()
        cert_hash = hashlib.sha256() #use the SHA256 hashing algorithm
        cert_hash.update(fr)
        data = cert_hash.hexdigest()
        print "\nYour Certificate hash is: ", data
        print "\nAdding to OP_RETURN..."
        #Opening Generation private key from pem file
        if os.path.isfile('./Generation_Private.pem'):
            print "\nGeneration Private Key file exists."
            sk = SigningKey.from_pem(open("Generation_Private.pem").read())
            sk_string = sk.to_string()
            sk = str(sk_string)
            sk = sk.encode("hex")
        elif os.path.isfile('./Generation_Private.pem.enc'):
            print "\nGeneration Private Key encoded file exists."
            decrypt_file(key, "Generation_Private.pem.enc")
            print "\nDecrypting Generation Private Key..."
            print "Saving to Generation_Private.pem..."
            sk = SigningKey.from_pem(open("Generation_Private.pem").read())
            sk_string = sk.to_string()
            sk = str(sk_string)
            sk = sk.encode("hex")
        else:
            print "\nGeneration Private Key does not exist."
            print "\nPlease place the file in the script directory or run -i option for a new key pair.\n"
            sys.exit()
        try:
            recipient_address = open("Cert_Address.txt", "rb").read()
            blockchain_client = BlockchainInfoClient()
            tx = make_op_return_tx(data, sk, blockchain_client, fee=1000, format='bin')
            broadcast_transaction(tx, blockchain_client)
        except Exception:
            print "\nNo balance in your Generation address.\n"
            print "Please load some bitcoins in order to submit your certificate.\n"
            
    sys.exit()


def certificateUpdate():
    sys.exit()


def certificateRevocation():
    sys.exit()


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):

    #Thanks to Eli Bendersky: https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):

    #Thanks to Eli Bendersky: https://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def main(argu):
    try:
        if argu[1] == "--help" or argu[1] == "-h":
            #Option to helo with the usage of the script
            print "Usage: \"Block_SSL.py <option>\""
            print "\nFor a list of options use the --list option."
            print "\n"

        elif argu[1] == "--list":
            #List of available options that the user can use
            print "Usage: \"Block_SSL.py <option>\""
            print "This is the list of options you can use with Block_SSL. \n"
            print "\t -i\t Identity Creation"
            print "\t -i\t Identity Update"
            print "\t -ii\t Identity Check"
            print "\t -cc\t Certificate Creation"
            print "\t -u\t Certificate Update"
            print "\t -r\t Certificate Revocation"
            print "\t -d\t Decrypt Private Key files"
            print "\n"

        elif argu[1] == "-i":
            #Identity Creation Script
            identityCreation()

        elif argu[1] == "-iu":
            #Identity Update Script
            identityUpdate()

        elif argu[1] == "-ii":
            #Identity Check Script
            identityCheck()

        elif argu[1] == "-cc":
            #Certificate Creation Script
            certificateCreation()

        elif argu[1] == "-u":
            #Certificate Update Script
            certificateUpdate()

        elif argu[1] == "-r":
            #Certificate Revocation Script
            certificateRevocation()

        elif argu[1] == "-d":
            #Private Key Decryption Script
            password = getpass.getpass("Give your password: ")  #Ask for encryption password
            key = hashlib.sha256(password).digest()

            #Generation Private key decryption
            if os.path.isfile('./Generation_Private.pem.enc'):
                print "\n Generation Private Key exists."
                decrypt_file(key, "Generation_Private.pem.enc")
                print "\nDecrypting Generation Private Key..."
                print "Saving to Generation_Private.pem..."
            else:
                print "\n Generation Private Key does not exist."

            #Certificate Private key decryption
            if os.path.isfile('./Certificate_Private.pem.enc'):
                print "\n Certificate Private Key exists."
                decrypt_file(key, "Certificate_Private.pem.enc")
                print "\nDecrypting Certificate Private Key..."
                print "Saving to Certificate_Private.pem..."
            else:
                print "\n Certificate Private Key does not exist."

            #Revocation Private key decryption
            if os.path.isfile('./Revocation_Private.pem.enc'):
                print "\n Revocation Private Key exists."
                decrypt_file(key, "Revocation_Private.pem.enc")
                print "\nDecrypting Revocation Private Key..."
                print "Saving to Revocation_Private.pem..."
            else:
                print "\n Revocation Private Key does not exist."

    except IndexError:
        print "Usage: \"Block_SSL.py <option>\""
        print "\nFor a list of options use the --list option."
        print "\nFor help use the --help or -h option."
        print "\n"


if __name__ == "__main__":
    main(sys.argv)
