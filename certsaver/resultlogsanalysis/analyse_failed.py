from typing import List
import json

input_file = "failed_connections.log"
#output_file = "new_last_failures.log"

incompatible_methods_counter = 0
eap_failure_counter = 0
unsupported_cipher_counter = 0
eap_method_counter = 0
peap_method_counter = 0
version_zero_count = 0

previous_line = ""
previous_domain = ""

failed_due_to_nak = False
eap_failure = False
unsupported_cipher = False
anonymous_reject = False
anonymous_reject_counter = 0

eap_method_proposal = False
peap_proposal = False
version_failure = False

last_domains = []




with open(input_file, "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("anonymous@"):
            if failed_due_to_nak:
                incompatible_methods_counter += 1
            if eap_failure:
                eap_failure_counter += 1
            if anonymous_reject:
                anonymous_reject_counter += 1
            if unsupported_cipher:
                unsupported_cipher_counter += 1
            if eap_method_proposal:
                eap_method_counter += 1
            if peap_proposal:
                peap_method_counter += 1
            if version_failure:
                version_zero_count += 1

            if peap_proposal and not unsupported_cipher and not version_failure and len(previous_domain)>0:
                #print(previous_domain)
                last_domains += [previous_domain]
            failed_due_to_nak = False
            eap_failure = False
            anonymous_reject = False
            unsupported_cipher = False
            eap_method_proposal = False
            peap_proposal = False
            version_failure = False
            previous_domain = line.removeprefix("anonymous@").removesuffix("\n")
        else:
            # if "CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=" in line:
            #     if "NAK" not in line:
            #         failed_due_to_nak = False
            #     else:
            #         failed_due_to_nak = True

            if "CTRL-EVENT-EAP-PROPOSED-METHOD" in line:
                eap_method_proposal = True
            if "CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25" in line:
                peap_proposal = True

            if "CTRL-EVENT-EAP-FAILURE EAP authentication failed" in line:
                eap_failure = True
                if "CTRL-EVENT-REGDOM-CHANGE init=COUNTRY_IE type=COUNTRY alpha2=BE" in previous_line:
                    anonymous_reject = True
                if "CTRL-EVENT-EAP-STARTED EAP authentication started" in previous_line:
                    anonymous_reject = True
                if "NAK" in previous_line:
                    failed_due_to_nak = True

            if "EAP-PEAP: Failed to select forced PEAP version 1" in line:
                version_failure = True

            if "SSL_connect error" in line:
                unsupported_cipher = True

        previous_line = line


# Handle the last block
if failed_due_to_nak:
    incompatible_methods_counter += 1
if eap_failure:
    eap_failure_counter += 1
if anonymous_reject:
    anonymous_reject_counter += 1
if unsupported_cipher:
    unsupported_cipher_counter += 1
if eap_method_proposal:
    eap_method_counter += 1
if peap_proposal:
    peap_method_counter += 1
if version_failure:
    version_zero_count += 1

if peap_proposal and not unsupported_cipher and not version_failure and len(previous_domain)>0:
    print(previous_domain)
    last_domains += [previous_domain]


print(f"{incompatible_methods_counter} profiles failed due to unsupported EAP method")
print(f"{eap_failure_counter} profiles attempted eap")
print(f"{unsupported_cipher_counter} unsupported ciphers")
print(f"{anonymous_reject_counter} anonymous rejects")
print(f"{eap_method_counter} proposed an eap method (anonymous id reject?)")
print(f"{peap_method_counter} proposed peap")
print(f"{version_zero_count} failed due to version zero")
#print(last_domains)
print(len(last_domains))
print(last_domains)

# store_file(last_domains, "last_realms.json")

