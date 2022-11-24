import os
import uuid
import xml.etree.ElementTree as ET
from cryptography.x509 import load_pem_x509_certificate as loadpem

#Create a random Guid like "1b55c048-38c0-4ac2-ab9a-f3fdf84c8afb"
def guidcertgen():
    certguid = str(uuid.uuid4())
    return (certguid)


#extract the base64 part of the certfile in a single string
def base64extract(certfile):
    cert_file_name = os.path.join(os.path.dirname(__file__), certfile)
    base64cert = open(cert_file_name, "r")
    lines = base64cert.readlines()
    lines = lines[1:-1]
    base64cert.close()
    certlist=[]
    for i in lines:
        certlist.append(i.rstrip())
    return ''.join(certlist)

#Build the XML
def certxml_create ( addreplace, certURI, certData):
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
    certxml_Data.text = base64extract (certData)
    build_file = ET.ElementTree( certxml_Start)
    build_file.write("xmlcert.xml")
    return ET.tostring( certxml_Start, encoding='UTF-8', method='xml')


#URI create
def certURI_builder ( isroot, certhash):
    URI = './Device/Vendor/MSFT/RootCATrustedCertificates/'+ isroot +'/'+ certhash +'/EncodedCertificate'
    return URI

print (certxml_create( 'Add', certURI_builder( 'Root', 'CERTHASH02281810'), 'cert.pem'))
