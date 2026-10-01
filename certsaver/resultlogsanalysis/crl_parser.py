#!/usr/bin/env python3
import json
import time
import pem
import os
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature

folder = "scrapedcerts/"
directory = os.fsencode(folder)
files = os.listdir(directory)

issuers_folder = "scrapedissuers/"
issuers_directory = os.fsencode(issuers_folder)
issuers_files = os.listdir(issuers_directory)
no_crl_count = 0
crl_but_no_issuer = []

cert_by_url = {}

with open('version1/crl_success.json') as f:
    jsn = json.load(f)
    print(len(jsn))
    already_checked = set(jsn)

# with open('version0/ldap.json') as f:
#     known_ldap = set(json.load(f))
#
# with open('version0/unsupported_crl.json') as f:
#     unsupported_crl = set(json.load(f))

with open("version1/max_retries.json") as f:
    known_connection_fail = set(json.load(f))

# with open("version0/invalid_signature.json") as f:
#     known_invalid_signature = set(json.load(f))
# #
# # with open("crl_fails/wrong_format.json") as f:
# #     known_crl_wrong_format = set(json.load(f))
#
# with open("version0/expired_crl.json") as f:
#     known_expired_crl = set(json.load(f))

# print(len(already_checked))

def get_issuer(name):
    for issuer_file in issuers_files:
        issuername = os.fsdecode(issuer_file)
        certs = pem.parse_file(issuers_folder + issuername)
        if name in issuername:
            return x509.load_pem_x509_certificate(str(certs[0]).encode())

for file in files:
    filename = os.fsdecode(file)
    if ((filename not in already_checked) and (filename not in known_connection_fail)):
        certs = pem.parse_file(folder + filename)
        if len(certs) > 1:
            print(certs)
        cert = x509.load_pem_x509_certificate(str(certs[0]).encode())

        try:
            crl_urls = []
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            for ad in ext:
                for crl_name in ad.full_name:
                    crl_urls.append(crl_name.value)
                    if crl_name.value not in cert_by_url:
                        cert_by_url[crl_name.value] = {filename}
                    else:
                        cert_by_url[crl_name.value].add(filename)
        except x509.ExtensionNotFound:
            no_crl_count += 1
        except IndexError as e:
            print(filename)
            print(e)
        except ValueError as e:
            print(filename)
            print(e)
    # except Exception as e:
    #     print(filename)
    #     print(e)


print(len(cert_by_url))
number_of_cert_checks = 0
for url in cert_by_url:
    number_of_cert_checks += len(cert_by_url[url])
print(number_of_cert_checks)
checked_certs = []
last_fetch = {}
delay = 1.0
processed_urls = set()
counter = 0
crl_expired = 0
checked_but_not_verified = []
revoked_certs = set()

unsupported_crl_format = 0
max_retries = []#known_connection_fail
ldap = []
no_crl_interpreting = []
expired_crl_certs = []
invalid_signature_certs = []
incorrectly_formatted_issuer = 0

for crl_url in cert_by_url:
    print(cert_by_url)
    try:
        print(counter)
        counter += 1

        # Rate limiting per host
        host = urlparse(crl_url).netloc
        now = time.time()
        if host in last_fetch and now - last_fetch[host] < delay:
            time.sleep(delay - (now - last_fetch[host]))
        last_fetch[host] = time.time()

        crl_data = requests.get(crl_url, timeout=5).content


        try:
            rev_list = x509.load_der_x509_crl(crl_data)
        except ValueError:
            rev_list = x509.load_pem_x509_crl(crl_data)

        for cert_name in cert_by_url[crl_url]:
            no_issuer = False
            certs = pem.parse_file(folder + cert_name)
            if len(certs) > 1:
                print(certs)
            cert = x509.load_pem_x509_certificate(str(certs[0]).encode())

            try:
                cert_issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            except IndexError:
                print(f"incorrectly formatted issuer {cert_name}")
                incorrectly_formatted_issuer += 1
                continue
            issuer = get_issuer(cert_issuer)
            if issuer is None:
                no_issuer = True
                crl_but_no_issuer += [cert_name]

            else:
                if isinstance(issuer.public_key(), rsa.RSAPublicKey):
                    issuer.public_key().verify(
                        rev_list.signature,
                        rev_list.tbs_certlist_bytes,
                        padding.PKCS1v15(),
                        rev_list.signature_hash_algorithm,
                    )
                elif isinstance(issuer.public_key(), ec.EllipticCurvePublicKey):
                    issuer.public_key().verify(
                        rev_list.signature,
                        rev_list.tbs_certlist_bytes,
                        ec.ECDSA(rev_list.signature_hash_algorithm),
                    )
                else:
                    print("Unsupported public key type")
                    raise RuntimeError("Unsupported public key type")

            now = datetime.now(timezone.utc)
            if rev_list.next_update_utc and rev_list.next_update_utc < now:
                crl_expired += 1
                for cert in cert_by_url[crl_url]:
                    expired_crl_certs += [cert]
                continue

            #cert_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value + str(cert.serial_number)
            if rev_list.get_revoked_certificate_by_serial_number(cert.serial_number) is None:
                if no_issuer:
                    print("Not verified")
                    checked_but_not_verified += [cert_name]
                else:
                    checked_certs += [cert_name]
            else:
                print("certificate seems revoked")
                print(cert_name)
                revoked_certs.add(cert_name)


        processed_urls.add(crl_url)
    except requests.exceptions.RequestException as e:
        print(f"{crl_url}: {cert_by_url[crl_url]}")
        print(e)
        if "Max retries exceeded with url:" in str(e):
            for cert in cert_by_url[crl_url]:
                max_retries += [cert]
        elif "No connection adapters were found" in str(e):
            for cert in cert_by_url[crl_url]:
                ldap += [cert]
    except ValueError as e:
        print(f"{crl_url}: {cert_by_url[crl_url]}")
        print(e)
        unsupported_crl_format += len(cert_by_url[crl_url])
        for cert in cert_by_url[crl_url]:
            no_crl_interpreting += [cert]
    except InvalidSignature as e:
        print(f"{crl_url}: {cert_by_url[crl_url]}")
        print(e)
        for cert in cert_by_url[crl_url]:
            invalid_signature_certs += [cert]
    except Exception as e:
        print(f"{crl_url}: {cert_by_url[crl_url]}")
        raise e


print(f"Number expired crl: {expired_crl_certs}")
print(f"Expired crl: {crl_expired}")

print(f"incorrectly formatted issuer: {incorrectly_formatted_issuer}")

print(f"Invalid signature crl: {invalid_signature_certs}")
print(f"Invalid signature crl: {len(invalid_signature_certs)}")

print(f"Checked certificates: {len(checked_certs)}")
print(checked_certs)

print(f"Unsupported crl format: {no_crl_interpreting}")
print(f"Unsupported crl format: {unsupported_crl_format}")

print(f"max_retries: {max_retries}")
print(f"max_retries: {len(set(max_retries))}")
print(f"ldap: {len(set(ldap))}")
print(f"ldap: {ldap}")


print(revoked_certs)
print(f"crl but no issuer: {crl_but_no_issuer}")
print(f"crl but no issuer: {len(crl_but_no_issuer)}")
print(f"Checked but not verified: {checked_but_not_verified}")
print(f"Amount checked but not verified: {len(checked_but_not_verified)}")




print(len(invalid_signature_certs))


# with open("version0/crl_success.json", "w") as fh:
#     json.dump(
#         checked_certs,
#         fh,
#         separators=(",", ":"),
#         allow_nan=False,
#         sort_keys=True,
#         ensure_ascii=True,
#     )
#     fh.write("\r\n")

