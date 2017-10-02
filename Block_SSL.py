#!/usr/bin/python

#Copyright 2017 Thomas Sermpinis (a.k.a. Cr0wTom)

#Permission is hereby granted, free of charge, to any person obtaining a copy of this software
#and associated documentation files (the "Software"), to deal in the Software without restriction,
#including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
#and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
#WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import sys, string

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
    elif argu[1] == "-ii":
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
