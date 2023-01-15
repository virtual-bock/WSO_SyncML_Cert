import os
import sys
import uuid
import xml.etree.ElementTree as ET
from cryptography.x509 import load_pem_x509_certificate as loadpem
from cryptography.hazmat.primitives import hashes
import binascii

# Script for Microsoft RootCATrustedCertificates CSP
# execute the script with argument filename
# "SyncML_cert.py cert.pem"

#Create a random Guid like "1b55c048-38c0-4ac2-ab9a-f3fdf84c8afb"
def guidcertgen():
    certguid = str(uuid.uuid4())
    return (certguid)

#create a a single base64String without the 'begin' and 'end certificate' string.
def base64extract():
    lines = certDatalist[1:-1]
    certstring=[]
    for i in lines:
        certstring.append(i.rstrip())
    return ''.join(certstring)

#Build the CSP structured XML
def certxml_create (addreplace, certURI):
    certxml_Start = ET.Element (addreplace)
    certxml_Guid = ET.SubElement (certxml_Start, 'CmdID')
    certxml_Guid.text = guidcertgen ()
    certxml_Item = ET.SubElement (certxml_Start, 'Item')
    certxml_Target = ET.SubElement (certxml_Item, 'Target')
    certxml_LocURI = ET.SubElement (certxml_Target, 'LocURI')
    certxml_LocURI.text = certURI
    certxml_Meta = ET.SubElement (certxml_Item, 'Meta')
    certxml_Format = ET.SubElement (certxml_Meta,'Format')
    certxml_Format.attrib = {"xmlns":"syncml:metinf"}
    certxml_Format.text = 'b64'
    certxml_Type = ET.SubElement (certxml_Meta, 'Type')
    certxml_Type.text = 'text/plain'
    certxml_Data = ET.SubElement (certxml_Item, 'Data')
    certxml_Data.text = base64extract ()
    build_file = ET.ElementTree(certxml_Start)
    # make it human readable with indentation
    ET.indent(build_file, space="    ", level=0)
    build_file.write("xmlcert.xml")
    print ("finish!")

#Read certificate data
def readCert ():
    certCheck = loadpem(bytes(''.join(certDatalist),'UTF-8'))
    #SHA1 fingerprint of the certificate
    fingerSHA1 = binascii.b2a_hex(certCheck.fingerprint(hashes.SHA1())).decode('UTF-8')
    #Line below is for testing
    #print ("The SHA1-thumbprint is: " + fingerSHA1)

    # is it a root certificate
    # issuer == subject = Root
    # issuer != subject = CA
    if certCheck.issuer == certCheck.subject:
        certType = "Root"
    else:
        certType = "CA"
    #Line below is for testing
    #print ("The certificate is:" + certType)
    return certType + '/' + fingerSHA1.upper()

def certURI_builder ():    
    URI = './Device/Vendor/MSFT/RootCATrustedCertificates/'+ readCert() +'/EncodedCertificate'
    return URI

# Open the file
# prepare the environment
# DERfile handling planed in future
print ("Reading the certificate")
cert_file = os.path.join(os.path.dirname(__file__), str(sys.argv[1]))
try:
    base64cert = open(cert_file, "r")
except FileNotFoundError:
    print ("File not found! Did you have type it correctly?")
    sys.exit(1)
except:
    print ("something went wrong!")
    sys.exit(1)

certDatalist = base64cert.readlines()
base64cert.close()

#Start XML creation
print ("Start to create the XML file.")
certxml_create('Add', certURI_builder())