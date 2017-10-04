#!/usr/bin/python

import sys, string, pybitcoin
# For pybitcoin download and install from: https://github.com/blockstack/pybitcoin.git

def identityCreation():
    ex = raw_input("Do you already own a BitCoin address that you want to use? [Y]es [N]o, default: [Y]")
    if ex == "Y" or ex == "y" or ex == "" or ex == " ":
        gen_priv = raw_input("Which is your private key?") #Private Key of the owner
        print "Saving to Generation_Private.pem file..."
        open("Generation_Private.pem","w").write(gen_priv.to_pem()) #Saving to file
        print "Generating \"Generation\" Public Key..."
        gen_pub = gen_priv.public_key() #Generate the "Generation" public key from gen_priv
        print "Saving to Generation_Public.pem file..."
        open("Generation_Public.pem","w").write(gen_pub.to_pem()) #Saving to file
        print "Public/Private key pair creation:"
        print "Warning: This is a pseudo-random generation."
        print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation."

    else:
        print "Public/Private key pair creation:"
        print "Warning: This is a pseudo-random generation."
        print "Warning: If you want complete randomness consider other ways of Public/Private key pair generation."

        print "Generating \"Generation\" Private Key..."
        gen_priv = BitcoinPrivateKey() #Generate the "Generation" private key
        print "Saving to Generation_Private.pem file..."
        open("Generation_Private.pem","w").write(gen_priv.to_pem()) #Saving to file
        print "Generating \"Generation\" Public Key..."
        gen_pub = gen_priv.public_key() #Generate the "Generation" public key from gen_priv
        print "Saving to Generation_Public.pem file..."
        open("Generation_Public.pem","w").write(gen_pub.to_pem()) #Saving to file

    print "Generating \"Certificate\" Private Key..."
    cert_priv = BitcoinPrivateKey() #Generate the "Certificate" private key
    print "Saving to Certificate_Private.pem file..."
    open("Certificate_Private.pem","w").write(cert_priv.to_pem()) #Saving to file
    print "Generating \"Certificate\" Public Key..."
    cert_pub = cert_priv.public_key()#Generate the "Certificate" public key from cert_priv
    print "Saving to Certificate_Public.pem file..."
    open("Certificate_Public.pem","w").write(cert_pub.to_pem()) #Saving to file

    print "Generating \"Revocation\" Private Key..."
    rev_priv = BitcoinPrivateKey() #Generate the "Revocation" private key
    print "Saving to Revocation_Private.pem file..."
    open("Revocation_Private.pem","w").write(rev_priv.to_pem()) #Saving to file
    print "Generating \"Revocation\" Public Key..."
    rev_pub = rev_priv.public_key() #Generate the "Revocation" public key from rev_priv
    print "Saving to Revocation_Public.pem file..."
    open("Revocation_Public.pem","w").write(rev_pub.to_pem()) #Saving to file

    print "\nYour addresses are:"
    print "\nGeneration Address: ", gen_pub.address()
    print "\nCertificate Address: ", cert_pub.address()
    print "\nRevocation Address: ", rev_pub.address()
    print "\nWarning: Please keep your Revocation address secret!"


def identityCheck():

def certificateCreation():

def certificateUpdate():

def certificateRevocation():

def main():
    argu = sys.argv
    if argu[1] == "--help" or argu[1] == "-h":
        #Option to helo with the usage of the script
        print "Usage: \"Block_SSL.py <option>\""
        print "\nFor a list of options use the --list option."
        print "\n"
        sys.exit()
    elif argu[1] == "--list":
        #List of available options that the user can use
        print "Usage: \"Block_SSL.py <option>\""
        print "This is the list of options you can use with Block_SSL. \n"
        print "\t -i\t Identity Creation"
        print "\t -ii\t Identity Check"
        print "\t -cc\t Certificate Creation"
        print "\t -u\t Certificate Update"
        print "\t -r\t Certificate Revocation"
        print "\n"
        sys.exit()
    elif argu[1] == "-i":
        #Identity Creation Script
        identityCreation()
        sys.exit()
    elif argu[1] == "-ii":
        #Identity Check Script
        identityCheck()
        sys.exit()
    elif argu[1] == "-cc":
        #Certificate Creation Script
        certificateCreation()
        sys.exit()
    elif argu[1] == "-u":
        #Certificate Update Script
        certificateUpdate()
        sys.exit()
    elif argu[1] == "-r":
        #Certificate Revocation Script
        certificateRevocation()
        sys.exit()

        '''
    elif len(argu) == 1:
        print "Usage: \"Block_SSL.py <option>\""
        print "\nFor a list of options use the --list option."
        print "\nFor help use the --help or -h option."
        print "\n"
        sys.exit()
        '''

main()
