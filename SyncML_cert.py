#!/usr/bin/env python3
import os
import sys
import uuid
import xml.etree.ElementTree as ET
from cryptography.x509 import load_pem_x509_certificate as loadpem
from cryptography.hazmat.primitives import hashes
import binascii

# Script for Workspace ONE UEM - Windows 10 Certificates (Microsoft RootCATrustedCertificates CSP)
# execute the script with arguments like:
# "SyncML_cert.py Replace cert.pem"
# I've created some exception to run it also without arguments

#Create a random Guid like "1b55c048-38c0-4ac2-ab9a-f3fdf84c8afb"
def guidcertgen():
    certguid = str( uuid.uuid4())
    return ( certguid)

#Create a a single base64-string without the 'BEGIN CERTIFICATE' and 'END CERTIFICATE' lines and no linefeed.
def base64extract():
    lines = cert64Data[ 1:-1]
    certstring=[]
    for i in lines:
        certstring.append( i.rstrip())
    return ''.join( certstring)

#Build the CSP structured XML
#planed to make "add" or "replace" variable
def certxml_create ( addreplace, certURI, fileName):
    certxml_Start = ET.Element ( addreplace)
    certxml_Guid = ET.SubElement ( certxml_Start, 'CmdID')
    certxml_Guid.text = guidcertgen ()
    certxml_Item = ET.SubElement ( certxml_Start, 'Item')
    certxml_Target = ET.SubElement ( certxml_Item, 'Target')
    certxml_LocURI = ET.SubElement ( certxml_Target, 'LocURI')
    certxml_LocURI.text = certURI
    certxml_Meta = ET.SubElement ( certxml_Item, 'Meta')
    certxml_Format = ET.SubElement ( certxml_Meta,'Format')
    certxml_Format.attrib = {"xmlns":"syncml:metinf"}
    certxml_Format.text = 'b64'
    certxml_Type = ET.SubElement ( certxml_Meta, 'Type')
    certxml_Type.text = 'text/plain'
    certxml_Data = ET.SubElement ( certxml_Item, 'Data')
    certxml_Data.text = base64extract ()
    build_file = ET.ElementTree( certxml_Start)
    #Make it human readable with indentation
    ET.indent( build_file, space="    ", level=0)
    build_file.write( fileName + ".xml")
    print ("First file created!")
    certDelxml_Start = ET.Element ( 'Delete')
    certDelxml_Guid = ET.SubElement ( certDelxml_Start, 'CmdID')
    certDelxml_Guid.text = guidcertgen ()
    certDelxml_Item = ET.SubElement ( certDelxml_Start, 'Item')
    certDelxml_Target = ET.SubElement ( certDelxml_Item, 'Target')
    certDelxml_LocURI = ET.SubElement ( certDelxml_Target, 'LocURI')
    certDelxml_LocURI.text = certURI
    buildDel_file = ET.ElementTree( certDelxml_Start)
    #Make it human readable with indentation
    ET.indent( buildDel_file, space="    ", level=0)
    buildDel_file.write( fileName + "_Remove.xml")
    print ("Files Finished!")

#Read certificate data
def readCert ():
    certCheck = loadpem(bytes(''.join( cert64Data),'UTF-8'))
    #SHA1 fingerprint of the certificate
    fingerSHA1 = binascii.b2a_hex( certCheck.fingerprint(hashes.SHA1())).decode('UTF-8')
    #Line below is for testing
    #print ("The SHA1-thumbprint is: " + fingerSHA1)

    # is it a root certificate
    # issuer == subject = Root
    # issuer != subject = CA
    if certCheck.issuer == certCheck.subject:
        certType = "Root"
    #    print(certCheck.issuer)
    #    print(certCheck.subject)
    else:
        certType = "CA"
    #    print(certCheck.issuer)
    #    print(certCheck.subject)
    return certType + '/' + fingerSHA1.upper()

def certURI_builder ():    
    URI = './Device/Vendor/MSFT/RootCATrustedCertificates/'+ readCert() +'/EncodedCertificate'
    return URI

def openCertFile ( certFile):
    # Open the file
    # prepare the environment
    # DERfile handling planed in future
    print ("Reading the certificate")
    try:
        cert_file = os.path.join( os.path.dirname(__file__), certFile)
    except:
        print ("I listen to what you say! Not my fault! Not my fault!")
    try:
        base64cert = open( cert_file, "r")
    except FileNotFoundError:
        print ("File not found! Did you have type it correctly?")
        sys.exit(1)
    except:
        print ("Something went wrong!")
        sys.exit(1)
    certDatalist = base64cert.readlines()
    base64cert.close()
    return certDatalist

def argCheck ():
    global fileName
    global certAddReplace
    try:
        certAddReplace = sys.argv[1]
    except IndexError:
        certAddReplace = "Replace"
        print ("noArgumen! using - Replace")
    try:
        fileName = sys.argv[2]
    except IndexError:
        fileName = "cert.pem"
        print ("No Argument! using - cert.pem")

argCheck()
cert64Data = openCertFile( fileName)

#Start XML creation
print ("Start to create the XML file.")
certxml_create ( certAddReplace, certURI_builder(), fileName)
