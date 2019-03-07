# This python script will download the publicly trusted Mozilla root CAs and 
# the DoD PKI root CAs to create a PEM file CA bundle to be used with PSHTT
# and SSLyze and other tools.

import os.path
import shutil
import re
import requests
import zipfile
from OpenSSL import crypto
import certifi
import argparse

cert_stores = {
    'DoD_Roots' : 'http://iasecontent.disa.mil/pki-pke/Certificates_PKCS7_v5.5_DoD.zip',
    'ECA_Roots' : 'http://iasecontent.disa.mil/pki-pke/Certificates_PKCS7_v5.4_ECA.zip',
    'JITC_Roots' : 'http://iasecontent.disa.mil/pki-pke/Certificates_PKCS7_v5.5_JITC.zip',
}

intermediate_certs = {
    'Entrust_L1K_Intermediate' : 'http://aia.entrust.net/l1k-chain256.cer',
    'Entrust_L1M_Intermediate' : 'http://aia.entrust.net/l1m-chain256.cer',
    'DigiCert_SHA2_EV_Intermediate' : 'http://cacerts.digicert.com/DigiCertSHA2ExtendedValidationServerCA.crt',
    'DigiCert_SHA2_Secure_Server_Intermediate' : 'http://cacerts.digicert.com/DigiCertSHA2SecureServerCA.crt',
    'IdenTrust_TrustID_Server_Intermediate' : 'http://validation.identrust.com/certs/trustidcaa52.p7c',
    'GeoTrust_RSA_Intermediate' : 'http://cacerts.geotrust.com/GeoTrustRSACA2018.crt',
    'GeoTrust_EV RSA_Intermediate' : 'http://cacerts.geotrust.com/GeoTrustEVRSACA2018.crt',
    'DigiCert_Global_CA_G2_Intermediate' : 'http://cacerts.digicert.com/DigiCertGlobalCAG2.crt',
    'DigiCert_SHA2_High_Assurance_Intermediate' : 'http://cacerts.digicert.com/DigiCertSHA2HighAssuranceServerCA.crt',
    'GoDaddy_Secure_CA_G2_Intermediate' : 'http://certificates.godaddy.com/repository/gdig2.crt',
}

all_certs = { **cert_stores, **intermediate_certs }
cache_dir = "./cache"
PTCertsPEM = "PTCerts.PEM"
PTCertsWithIntermediates = "PTCertsWithIntermediates.PEM"
AllCertsPEM = "AllCerts.pem"

def get_certificates(self):
    from OpenSSL.crypto import _lib, _ffi, X509
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """
    
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)

def download_certificates_and_create_PEM(cert_type, url):
    """
    Download cert_type certificate bundle from url and extract the files from it and create PEM 
    """
    pem_file = "{}/{}_CABundle.pem".format(cache_dir, cert_type)
    if os.path.exists(pem_file) == False:
        filename = None
        parts = url.split('.')
        extension = parts[(len(parts) - 1)].lower()
        zip_type = False
        if(extension == "zip"):
            zip_type = True
        filename = "{}/{}.{}".format(cache_dir, cert_type, extension)
        if os.path.exists(filename) == False:
            if("http://" in url or "https://" in url):
                # Download CA certs
                # todo: in the future could parse PKI-PKE page in IASE to get latest version, but for now just direct download
                print("Downloading {} CA certs...".format(cert_type))
                try:
                    r = requests.get(url)
                except Exception as err:
                    print("Error downloading {} CA certs: {}".format(cert_type, err))
                    return None
                with open(filename, 'wb') as dl_file:
                    dl_file.write(r.content)
                print("Finished downloading {} CA certs.".format(cert_type))
            elif(os.path.exists(url) == True):
                with open(url, 'rb') as sourcefile:
                    with open(filename, 'wb') as destfile:
                        destfile.write(sourcefile.read())
                print("Finished copying {} CA certs.".format(cert_type))
            else:
                print("Error: Unable to get {} CA certs.".format(cert_type))
                return
        else:
            print("Already downloaded {} CA certs.".format(cert_type))

        if(zip_type is True):
            print("Unzipping {} CA certs...".format(cert_type))
            zip_file = zipfile.ZipFile(filename, 'r')
            cert_directory = "./{}/{}_Certs/".format(cache_dir, cert_type)
            zip_file.extractall(cert_directory)
            zip_file.close()
            print("Finished unzipping {} CA certs.".format(cert_type))

            #find P7B
            p7b_file = None
            for (dirpath, dirnames, filenames) in os.walk(cert_directory):
                for filename in filenames: 
                    if filename.lower().endswith(".pem.p7b"):
                        p7b_file = os.path.join(dirpath, filename)
            if p7b_file is None:
                print("Unable to find {} p7b file.".format(cert_type))
                return None
            filename = p7b_file
            extension = "p7b"
        
        print("Loading {} cert data...".format(cert_type))
        with open(filename, 'rb') as cert_file:
            if(extension == "p7b"):
                cert_data = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, cert_file.read())
                certs = get_certificates(cert_data)
                print("Found {} certs.".format(len(certs)))
            elif(extension == "p7c"):
                cert_data = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, cert_file.read())
                certs = get_certificates(cert_data)
                print("Found {} certs.".format(len(certs)))
            else:
                cert_data = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_file.read())
                certs = [cert_data]
        print("Writing {} Certs to PEM file...".format(cert_type))
        with open(pem_file, 'ab') as pem:
            for cert in certs:
                certPEM = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                pem.write(certPEM)
        print("Finished writing {} Certs to PEM file.".format(cert_type))
        return pem_file
    else:
        print("Already created {} CA PEM file.".format(cert_type))
        return pem_file

parser = argparse.ArgumentParser(description='Create custom trust store bundle.')
parser.add_argument('-c', '--clean', action='store_true', help='Start clean by deleting older cached items and pem files.')
args = parser.parse_args()

if(args.clean):
    print("Cleaning cache and previous PEM files...")
    shutil.rmtree(cache_dir)
    print("Deleted cache directory.")
    files = [PTCertsWithIntermediates, PTCertsPEM, AllCertsPEM]
    for f in files:
        if(os.path.exists(f)):
            os.remove(f)
            print("Deleted {} file.".format(f))

if(os.path.exists(cache_dir) == False):
    os.mkdir(cache_dir)
if os.path.exists(AllCertsPEM) == False:
    pem_files = []
    for cert_type, cert_url in all_certs.items():
        pem_file = download_certificates_and_create_PEM(cert_type, cert_url)
        if(pem_file is not None):
            pem_files.append(pem_file)
    
    if os.path.exists(PTCertsPEM) == False:
        print("Getting publicly trusted certs PEM file...")
        with open(certifi.where(), 'rb') as certifile:
            with open(PTCertsPEM, 'wb') as ptfile:
                ptfile.write(certifile.read())
        print("Finished getting publicly trusted certs PEM file.")
        pem_files.append(PTCertsPEM)
    else:
        print("Already have publicly trusted PEM file.")
        pem_files.append(PTCertsPEM)

    print("Creating Public Trust with Intermediate Certs bundle...")
    with(open(PTCertsWithIntermediates, 'wb')) as ptintpem:
        for pem_file in pem_files:
            if("PTCerts" in pem_file or "Public_Trust" in pem_file or "Intermediate" in pem_file):
                with open(pem_file, 'rb') as pem:
                    ptintpem.write(pem.read())
    print("Finished creating Public Trust with Intermediate Certs bundle.")      

    print("Creating combined all certs bundle...")            
    with open(AllCertsPEM, 'wb') as allpem:
        for pem_file in pem_files:
            with open(pem_file, 'rb') as pem:
                allpem.write(pem.read())
    print("Finished creating combined all certs bundle.")
    
else:
    # todo: check date on CA bundle, and get new if too old
    print("All certs CA bundle already ready.")
