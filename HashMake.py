#!/usr/bin/python
import hashlib
import string
CN = raw_input("Which is the primary Host Name of your website (Common Name - CN)?") #Common Name
O = raw_input("Which is the Organizations name?") #Organization
O.replace(" ", "_") #Replace the spaces of the Organization with underscores
PK = raw_input("Which is your publick key?") #Public Key of the owner
FS = CN + ";" + O + ";" + PK + ";" #Final String - concatenation
m = hashlib.md5()
m.update(FS)
print "The string for hashing is %s" % FS
print m.hexdigest()
