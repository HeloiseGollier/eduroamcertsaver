#!/usr/bin/env python3
import pem
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

folder = "scrapedcerts/"
directory = os.fsencode(folder)
files = os.listdir(directory)

all_urls = []

with open("crl_fails/expired_crl.json") as f:
    known_expired_crl = set(json.load(f))

for file in files:
    filename = os.fsdecode(file)
    certs = pem.parse_file(folder + filename)
    if len(certs) > 1:
        print(certs)
    cert = x509.load_pem_x509_certificate(str(certs[0]).encode())

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        for ad in ext:
            for crl_name in ad.full_name:
                all_urls.append(crl_name.value)
                # if crl_name.value not in cert_by_url:
                #     cert_by_url[crl_name.value] = {filename}
                # else:
                #     cert_by_url[crl_name.value].add(filename)
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        print(e)


print(len(all_urls))


