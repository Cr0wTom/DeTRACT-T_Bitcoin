#!/usr/bin/python

import sys, string, pybitcoin, hashlib, os, random, struct, getpass
from Crypto.Cipher import AES
from pybitcoin import BitcoinPrivateKey
#For pybitcoin download and install from:
#https://github.com/blockstack/pybitcoin.git


def identityCreation():
    ex = raw_input("Do you already own a BitCoin address that you want to use? [Y]es [N]o, default: [Y]")
    if ex == "Y" or ex == "y" or ex == "" or ex == " ":
        gen_priv = raw_input("Which is your private key?")  #Private Key of the owner
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
        print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation."

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


def identityCheck():
    sys.exit()


def certificateCreation():
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
        print "\t -ii\t Identity Check"
        print "\t -cc\t Certificate Creation"
        print "\t -u\t Certificate Update"
        print "\t -r\t Certificate Revocation"
        print "\t -d\t Decrypt Private Key files"
        print "\n"

    elif argu[1] == "-i":
        #Identity Creation Script
        identityCreation()

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

    elif argu[1] is None:
        print "Usage: \"Block_SSL.py <option>\""
        print "\nFor a list of options use the --list option."
        print "\nFor help use the --help or -h option."
        print "\n"


if __name__ == "__main__":
    main(sys.argv)
