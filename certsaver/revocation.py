#!/usr/bin/env python3
from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier, NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509 import ocsp
import pem
import seaborn
import os
import requests

from typing import List
import json

folder = "scrapedcerts/"
directory = os.fsencode(folder)
files = os.listdir(directory)

issuers_folder = "scrapedissuers/"
issuers_directory = os.fsencode(issuers_folder)
issuers_files = os.listdir(issuers_directory)

ocsp_count = 0
no_ocsp_count = 0
crl_count = 0
no_crl_count = 0
ocsp_only = 0
has_ocsp = False
crl_only = 0
crl = False
support_nothing = 0
ocsp_but_no_issuer_count = 0
crl_but_no_issuer_count = 0

no_ocsp_url = 0

ocsp_request_actually_succesful = 0
ocsp_request_unauthorized = 0
ocsp_request_other = []

connection_timeout = 0
parsing_error = 0

ocsp_certs = []

crl_files = []


headers = {
    "Content-Type": "application/ocsp-request",
    "Accept": "application/ocsp-response",
}

def get_issuer(name):
    for issuer_file in issuers_files:
        issuername = os.fsdecode(issuer_file)
        certs = pem.parse_file(issuers_folder + issuername)
        if name in issuername:
            return x509.load_pem_x509_certificate(str(certs[0]).encode())

# print(f"Already verified {len(already_verified)} certificates.")
for file in files:
    filename = os.fsdecode(file)

    # if filename in already_verified:
    #     continue

    certs = pem.parse_file(folder + filename)
    if len(certs) > 1:
        print(certs)
    cert = x509.load_pem_x509_certificate(str(certs[0]).encode())


    try:
        ocsp_urls = []
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
        for ad in ext:
            #print(ad)
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(ad.access_location.value)
        if len(ocsp_urls) > 1:
            print("URLs: " + str(ocsp_urls))

        if len(ocsp_urls) == 0:
            #print("Ext: " + filename + " " + str(ext))
            no_ocsp_count += 1

        else:
            has_ocsp = True
            ocsp_certs += [filename]
            ocsp_count += 1

            try:
                cert_issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                issuer_cert = get_issuer(cert_issuer)
            except Exception as e:
                print(filename)
                print(e)
                ocsp_but_no_issuer_count += 1
                continue

            if issuer_cert is None:
                ocsp_but_no_issuer_count += 1
            else:
                if len(ocsp_urls) >0:
                    builder = ocsp.OCSPRequestBuilder()
                    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
                    request = builder.build()
                    ocsp_request_data = request.public_bytes(Encoding.DER)

                    resp = requests.post(
                        ocsp_urls[0],
                        data=ocsp_request_data,
                        headers=headers,
                        timeout=5,
                    )
                    ocsp_resp = ocsp.load_der_ocsp_response(resp.content)
                    if ocsp_resp.response_status == OCSPResponseStatus.SUCCESSFUL:
                        ocsp_request_actually_succesful += 1
                        ocsp_certs += [filename]
                    elif ocsp_resp.response_status == OCSPResponseStatus.UNAUTHORIZED:
                        ocsp_request_unauthorized += 1
                    else:
                        ocsp_request_other += [ocsp_resp.response_status]
                else:
                    no_ocsp_url += 1
    except x509.ExtensionNotFound:
        no_ocsp_count += 1
    except Exception as e:
        if "Max retries exceeded with url:" in str(e):
            connection_timeout += 1
        elif "parsing asn1 value: ParseError" in str(e):
            parsing_error += 1
        else:
            print(filename)
            print(e)

    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        crl = True
        crl_count += 1
        crl_files += [filename]
    except x509.ExtensionNotFound:
        no_crl_count += 1
    except Exception as e:
        print(filename)
        print(e)

    if has_ocsp and not crl:
        ocsp_only += 1
    if crl and not has_ocsp:
        crl_only += 1
    if not crl and not has_ocsp:
        if "BI" in filename:
            print(f"{filename} supports nothing")
        support_nothing +=1
    has_ocsp = False
    crl = False

print(ocsp_certs)

print(f"Total ocsp: {ocsp_count}") # 1378 +2
print(f"No ocsp: {no_ocsp_count}") # 839 +1
print(f"Total crls: {crl_count}") # 1752 +2
print(f"No crl: {no_crl_count}") # 465 +1
print(f"OCSP no crl: {ocsp_only}") # 103
print(f"crl no OCSP: {crl_only}") # 477
print(f"Support nothing: {support_nothing}") # 365 +1


print(f"ocsp but no issuer: {ocsp_but_no_issuer_count}")

print(f"Actual successful ocsp requests: {ocsp_request_actually_succesful}")
print(f"Unauthorized ocsp response: {ocsp_request_unauthorized}")
print(f"Other OCSP responses: {ocsp_request_other}")
print(f"Unsuccessful connection: {connection_timeout}")
print(f"Parsing errors: {parsing_error}")

# with open("version1/ocsp_success.json", "w") as fh:
#     json.dump(
#         ocsp_certs,
#         fh,
#         separators=(",", ":"),
#         allow_nan=False,
#         sort_keys=True,
#         ensure_ascii=True,
#     )
#     fh.write("\r\n")

