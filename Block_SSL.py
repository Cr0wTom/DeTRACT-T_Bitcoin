#!/usr/bin/python

import sys
import string
import hashlib
import os
import random
import struct
import getpass
import datetime
import json
import requests #pip install requests
import traceback
import subprocess
from datetime import timedelta
from Crypto.Cipher import AES
from pybitcoin import BitcoinPrivateKey, make_op_return_tx, BlockchainInfoClient, send_to_address
from OpenSSL import crypto, SSL
from ecdsa import SigningKey
#For pybitcoin download and install from:
#https://github.com/blockstack/pybitcoin.git

art = r'''

  ____  _            _           _____ _____ _
 |  _ \| |          | |         / ____/ ____| |v0.3
 | |_) | | ___   ___| | _______| (___| (___ | |
 |  _ <| |/ _ \ / __| |/ /______\___ \\___ \| |
 | |_) | | (_) | (__|   <       ____) |___) | |____
 |____/|_|\___/ \___|_|\_\     |_____/_____/|______|

 Block-SSL - SSL/TLS Certificate Authority Replacement
        through the BitCoin Blockchain

 Thesis Project - Aristotle University of Thessaloniki

                    By Cr0wTom

 ------------------------------------------------------

'''

def identityCreation():
    print art
    print "\nIdentity Creation Script - Block SSL\n"
    keybaseCheck()
    ans1 = raw_input("Do you own a Keybase.io account? [Y]es [N]o, default: [Y]\n")
    if ans1 == "Y" or ans1 == "y" or ans1 == "" or ans1 == " ":
        os.system("keybase version") #check for keybase version
        print "Checking for Updates...\n"
        os.system("echo 3 | keybase update check >/dev/null 2>&1") #check for keybase updates without terminal output
        os.system("keybase login") #login to keybase through terminal
    else:
        os.system("keybase version")
        print "Checking for Updates...\n"
        os.system('echo 3 | keybase update check >/dev/null 2>&1')
        os.system("keybase signup") #signup to keybase through terminal
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
    certadd = cert_pub.address()
    os.system("echo 3 | keybase currency add --force " + certadd + " >/dev/null 2>&1") #add cert address to keybase account
    print "\nCertificate address added to your keybase.io account.\n"
    print "\nPlease load your Generation and Revocation addresses with some satoshis."
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
    print art
    print "\nIdentity Update Script - Block SSL\n"
    keybaseCheck()
    print "Which way do you want to update your digital Identity - Generation Address? default: [1]\n"
    print "\t1. Generate Social Media Proof\n"
    print "\t2. DNS Proof\n"
    print "\t3. Add PGP Key\n"
    print "\t4. Create a new PGP Key\n"
    print "\t5. Follow a user\n"
    ans1 = raw_input()
    if ans1 == "1" or ans1 == "" or ans1 == " ":
        print "\nSelect the service you want to Proof:\n"
        print "\t1. Facebook\n"
        print "\t2. GitHub\n"
        print "\t3. Twitter\n"
        print "\t4. HackerNews\n"
        print "\t5. Reddit\n"
        ans2 = raw_input()
        if ans2 == "1":
            service = "facebook "
            username = raw_input("\nGive your Facebook Username: ")
            s = True
        elif ans2 == "2":
            service = "github "
            username = raw_input("\nGive your GitHub Username: ")
            s = True
        elif ans2 == "3":
            service = "twitter "
            username = raw_input("\nGive your Twitter Username: ")
            s = True
        elif ans2 == "4":
            service = "hackernews "
            username = raw_input("\nGive your HackerNews Username: ")
            s = True
        elif ans2 == "5":
            service = "reddit "
            username = raw_input("\nGive your Reddit Username: ")
            s = True
        else:
            s = False
        if s == True:
            command = "keybase prove " + service + username
            os.system(command)
        else:
            print "\nPlease run the script again, with a valid option."
            sys.exit()
    elif ans1 == "2":
        dns = raw_input("\nGive your DNS: ")
        dns = "keybase prove dns " + dns
        os.system(dns)
    elif ans1 == "3":
        raw_input("Plase your private pgp key to pgp.txt file, in the scripts directory, and press Enter.")
        os.system("keybase pgp import -i pgp.txt")
    elif ans1 == "4":
        print "\nCreating a new key pair:"
        print "Warning: This is a pseudo-random generation.\n"
        os.system("keybase pgp gen")
    elif ans1 == "5":
        user = raw_input("\nGive the users username: ")
        user = "keybase track " + user
        os.system(user)
    else:
        print "\nPlease run the script again, with a valid option."
        sys.exit()
    #generate new proof keybase prove
    sys.exit()



def identityCheck():
    #checks for the personal keybase identity of the user
    print art
    keybaseCheck()
    print "Keybase Followers: \n"
    os.system("keybase list-followers")
    print "\nKeybase Following: \n"
    os.system("keybase list-following")
    print "\nKeybase Devices: \n"
    os.system("keybase device list")
    print "\nGeneral User Info: \n"
    os.system("keybase id")
    print "\n"
    sys.exit()


def certificateCreation():
    print art
    print "\nCertificate Creation Script - Block SSL\n"
    # create a key pair
    print "Creating a new key pair:"
    print "Warning: This is a pseudo-random generation.\n"
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)

    # create a self-signed cert
    cert = crypto.X509()
    createCert(k, cert)

    open("certificate.crt", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    open("keys.key", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
    print "\nCertificate created in file: certificate.crt"
    print "\nKeys saved in file: keys.key\n"

    ans2 = raw_input("Do you have available satoshis in your Generation address? [Y]es [N]o, default: [Y]")
    if ans2 == "Y" or ans2 == "y" or ans2 == "" or ans2 == " ":
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
            blockchain_client = BlockchainInfoClient("dacc6a40-1b8f-4dbb-afc7-bc9657603e83")
            send_to_address(recipient_address, 164887, sk, blockchain_client) #make a ~10$ transactrion to cert address
            print "\nWait at least 20 minutes, and run the script with option -s to send the certificate to the blockchain."
        except Exception:
            print "\nNo balance in your Generation address.\n"
            print "Please load some bitcoins in order to submit your certificate.\n"

    else:
        print "Please load your Generation address and run the script again."

    sys.exit()


def certificateUpdate():
    print art
    print "\nCertificate Update Script - Block SSL\n"
    # create a key pair or use the old one
    ans = raw_input("Do you have your old keys.key file with your key pair? [Y]es [N]o, default: [Y]\n")
    if ans == "n" or ans == "N":
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        print "Creating a new key pair:"
        print "Warning: This is a pseudo-random generation.\n"
    else:
        print "Place your keys.key file in the scripts directory.\n"
        k = crypto.PKey()
        with open("keys.key", "r") as k:
            k = crypto.load_privatekey(crypto.FILETYPE_PEM, k.read())

    # create a self-signed cert
    cert = crypto.X509()
    createCert(k, cert)

    open("certificate.crt", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    print "\nCertificate created in file: certificate.crt"
    if ans == "n" or ans == "N":
        open("keys.key", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        print "\nKeys saved in file: keys.key\n"

    ans2 = raw_input("Do you want to send your certificate to the blockchain? [Y]es [N]o, default: [Y]")
    if ans2 == "Y" or ans2 == "y" or ans2 == "" or ans2 == " ":
        i = 2
        sendCertificate(i)

    sys.exit()


def certificateRevocation():
    print art
    print "\nCertificate Revocation Script - Block SSL\n"
    print "In which of your addresses do you still have access? default: [1]\n"
    print "\t1. All of the addresses. (Generation, Certificate, Revocation)\n"
    print "\t2. Only Certificate address.\n"
    print "\t3. Only Revocation address.\n"
    print "\t4. Revocation and Generation addresses.\n"
    ans = raw_input()
    blockchain_client = BlockchainInfoClient("dacc6a40-1b8f-4dbb-afc7-bc9657603e83")
    if ans == "1" or ans == "" or ans == " " or ans == "2":
        address = open("Cert_Address.txt", "r").read()
        address = address.strip()
        url = "https://blockchain.info/balance?format=json&active=" + address
        r = requests.get(url)
        try:
            balance = r.json()[address]
            balance = str(balance)
            x = 1
            i = 19
            final_balance = ""
            while x == 1:
                if balance[i] == ",":
                    x += 1
                else:
                    final_balance = final_balance + balance[i]
                    i += 1
            print "\nYour Certificate address balance is: " + final_balance
            #Opening Generation private key from pem file
            if os.path.isfile('./Certificate_Private.pem'):
                print "\nCertificate Private Key file exists."
                sk = SigningKey.from_pem(open("Certificate_Private.pem").read())
                sk_string = sk.to_string()
                sk = str(sk_string)
                sk = sk.encode("hex")
            elif os.path.isfile('./Certificate_Private.pem.enc'):
                print "\nCertificate Private Key encoded file exists."
                decrypt_file(key, "Certificate_Private.pem.enc")
                print "\nDecrypting Certificate Private Key..."
                print "Saving to Certificate_Private.pem..."
                sk = SigningKey.from_pem(open("Certificate_Private.pem").read())
                sk_string = sk.to_string()
                sk = str(sk_string)
                sk = sk.encode("hex")
            else:
                print "\nCertificate Private Key does not exist."
                print "\nPlease place the .pem file in the script directory.\n"
                sys.exit()
        except ValueError, e:
            raise Exception('Invalid response from blockchain.info.')
        if ans == "1" or ans == "" or ans == " ":
            recepient_address = open("Gen_Address.txt", "rb").read()
            ans3 = raw_input("Which is your revocation reason?\n")
            size = len(ans3)
            while size > 75:
                print "String too long for OP_RETURN transaction, please repeat.\n"
                ans3 = raw_input("Which is your revocation reason?\n")
                size = len(ans3)
            data = "R1: " + ans3
        else:
            recepient_address = raw_input("Give the address that you want to sent the certificate balance, for revocation purposes:\n")
            data = "R2: No access to Generation address"
            #todo - check if the address is correct
        try:
            tx = make_op_return_tx(data, sk, blockchain_client, fee=1000, format='bin')
            broadcast_transaction(tx, blockchain_client)
            final_balance = final_balance - 1000
            send_to_address(recipient_address, final_balance, sk, blockchain_client)
        except Exception:
            print "\nNo balance in your Certificate address.\n"
            print "If the Certificate address has 0 balance, it has been already been revoced.\n"
    elif ans == "3" or ans == "4":
        if os.path.isfile('./Revocation_Private.pem'):
            print "\nRevocation Private Key file exists."
            sk = SigningKey.from_pem(open("Revocation_Private.pem").read())
            sk_string = sk.to_string()
            sk = str(sk_string)
            sk = sk.encode("hex")
        elif os.path.isfile('./Revocation_Private.pem.enc'):
            print "\nRevocation Private Key encoded file exists."
            decrypt_file(key, "Revocation_Private.pem.enc")
            print "\nDecrypting Revocation Private Key..."
            print "Saving to Revocation_Private.pem..."
            sk = SigningKey.from_pem(open("Revocation_Private.pem").read())
            sk_string = sk.to_string()
            sk = str(sk_string)
            sk = sk.encode("hex")
        else:
            print "\nRevocation Private Key does not exist."
            print "\nPlease place the .pem file in the script directory.\n"
            sys.exit()
        if os.path.isfile('./Cert_Address.txt'):
            recepient_address = open("Cert_Address.txt", "rb").read()
        else:
            print "\nCert_Address.txt does not exist."
            recepient_address = raw_input("Give the Certificate address of your certificate, for the Extreme revocation transaction:\n")
        if ans == "3":
            data = "ER1: No Access to Generation and Certificate address"
        else:
            data = "ER2: No Access to Certificate address"
        #send all the balance to given address address
        print "\nYour revocation reason is: ", data
        print "\nAdding revocation reason to OP_RETURN..."
        try:
            send_to_address(recipient_address, 10000, sk, blockchain_client)
            tx = make_op_return_tx(data, sk, blockchain_client, fee=1000, format='bin')
            broadcast_transaction(tx, blockchain_client)
        except Exception:
            print "\nNo balance in your Revocation address.\n"
            print "Please load some bitcoins in order to submit your revocation reason.\n"
    sys.exit()


def createCert(k, cert):
    # create a self-signed cert
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
        an = int(raw_input("For how long do you need to update the certificate in days? (maximum: 365)\n"))
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
    return cert


def sendCertificate(i):
    if i == 1:
        ans = raw_input("Do you want to Create or Update your certificate? [C]reate [U]pdate, default: [C]")
        if ans == "C" or ans == "c" or ans == "" or ans == " ":
            mode = "CC: "
        else:
            mode = "UC: "
    elif i == 2:
        mode = "UC: "
    #Hashing of the certificate
    f = open("certificate.crt", "rb") #read file in binary mode
    fr = f.read()
    cert_hash = hashlib.sha256() #use the SHA256 hashing algorithm
    cert_hash.update(fr)
    data = cert_hash.hexdigest()
    print "\nYour Certificate hash is: ", data
    data = mode + data
    print "\nAdding to OP_RETURN..."
    #Opening Generation private key from pem file
    if os.path.isfile('./Certificate_Private.pem'):
        print "\nCertificate Private Key file exists."
        sk = SigningKey.from_pem(open("Certificate_Private.pem").read())
        sk_string = sk.to_string()
        sk = str(sk_string)
        sk = sk.encode("hex")
    elif os.path.isfile('./Certificate_Private.pem.enc'):
        print "\nCertificate Private Key encoded file exists."
        decrypt_file(key, "Certificate_Private.pem.enc")
        print "\nDecrypting Certificate Private Key..."
        print "Saving to Certificate_Private.pem..."
        sk = SigningKey.from_pem(open("Certificate_Private.pem").read())
        sk_string = sk.to_string()
        sk = str(sk_string)
        sk = sk.encode("hex")
    else:
        print "\nCertificate Private Key does not exist."
        print "\nPlease place the file in the script directory or run -i option for a new key pair.\n"
        sys.exit()
    try:
        blockchain_client = BlockchainInfoClient("dacc6a40-1b8f-4dbb-afc7-bc9657603e83")
        tx = make_op_return_tx(data, sk, blockchain_client, fee=10000, format='bin')
        broadcast_transaction(tx, blockchain_client)
    except Exception:
        print "\nNo balance in your Certificate address.\n"
        print "Please first run the -cc or the -u script.\n"


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*4096):

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


def decrypt_file(key, in_filename, out_filename=None, chunksize=64*4096):

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


def keybaseCheck():
    name = "keybase"
    try: #check if keybase exists
        devnull = open(os.devnull)
        subprocess.Popen([name], stdout=devnull, stderr=devnull).communicate()
        print "\tKeybase exists.\n"
    except OSError as e: #install keybase - os specific
            if e.errno == os.errno.ENOENT:
                if sys.platform == "linux" or sys.platform == "linux2": #todo - currently only ubuntu based .deb files
                    print "Downloading Keybase.dmg"
                    os.system("curl -O https://prerelease.keybase.io/keybase_amd64.deb")
                    print "Type your SuperUser Password:\n"
                    os.system("sudo dpkg -i keybase_amd64.deb")
                    os.system("sudo apt-get install -f")
                elif sys.platform == "win32": #all Windows versions - run with powershell
                    print "Downloading Keybase.exe\n"
                    #download and run of the installation .exe with powershell
                    subprocess.call(["C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", "$down = New-Object System.Net.WebClient; $url = 'https://prerelease.keybase.io/keybase_setup_386.exe'; $file = 'keybase_setup_386.exe'; $down.DownloadFile($url,$file); $exec = New-Object -com shell.application; $exec.shellexecute($file); exit;"])
                elif sys.platform == "darwin": #all OSX versions
                    print "Downloading Keybase.dmg"
                    os.system("curl -O https://prerelease.keybase.io/Keybase.dmg")
                    print "Type your SuperUser Password:\n"
                    os.system("sudo hdiutil attach keybase.dmg")
                    os.system("sudo cp -ir /Volumes/Keybase/Keybase.app /Applications")


def main(argu):
    try:
        if argu[1] == "--help" or argu[1] == "-h":
            #Option to helo with the usage of the script
            print art
            print "Usage: \"Block_SSL.py <option>\""
            print "\nFor a list of options use the --list option."
            print "\n"

        elif argu[1] == "--list":
            #List of available options that the user can use
            print art
            print "Usage: \"Block_SSL.py <option>\""
            print "This is the list of options you can use with Block_SSL. \n"
            print "\t -i\t Identity Creation"
            print "\t -i\t Identity Update"
            print "\t -ii\t Identity Check"
            print "\t -cc\t Certificate Creation"
            print "\t -u\t Certificate Update"
            print "\t -r\t Certificate Revocation"
            print "\t -s\t Send Certificate"
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

        elif argu[1] == "-s":
            #Certificate Revocation Script
            i = 1
            sendCertificate(i)

        elif argu[1] == "-d":
            print art
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
        else:
            print art
            print "Usage: \"Block_SSL.py <option>\""
            print "\nFor a list of options use the --list option."
            print "\nFor help use the --help or -h option."
            print "\n"

    except IndexError:
        print art
        print "Usage: \"Block_SSL.py <option>\""
        print "\nFor a list of options use the --list option."
        print "\nFor help use the --help or -h option."
        print "\n"


if __name__ == "__main__":
    main(sys.argv)
