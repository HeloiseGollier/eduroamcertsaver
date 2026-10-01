import json
from collections import Counter
from os import walk
import re

#certfilenames = []
#for (dirpath, dirnames, filenames) in walk("../../scrapedcerts"):
#     certfilenames.extend(filenames)
#     break

desired_lines = {"OpenSSL:", "EAP:", "PEAP:", "CTRL-EVENT", "anonymous@", "EAP-PEAP:", "fatal:bad certificate status response"}
pattern = re.compile("|".join(map(re.escape, desired_lines)))

realms = json.load(open('realms.json'))
print(len(realms))


input_file = "version0/session.log"
output_file = "version0/failed_connections.log"
condensed_file = "version0/condensed_file.log"

def condense_file(in_filename, out_filename):
    with open(in_filename, "r", encoding="utf-8", errors="replace") as infile, open(out_filename, "w") as outfile:
        for line in infile:
            if pattern.search(line):
                outfile.write(line)

def store_file(realms_lst, filename):
    with open(filename, "w") as fh:
        json.dump(
            realms_lst,
            fh,
            separators=(",", ":"),
            allow_nan=False,
            sort_keys=True,
            ensure_ascii=True,
        )
        fh.write("\r\n")


def find_failed_connections(in_filename, out_filename):
    failed_blocks = []
    current_block = []

    cert_names = set()
    saw_cert = False
    new_block = True
    blocks = 0
    duplicated_certs = 0
    previous_line = ""
    domains = []

    ver_1_domains = []


    with open(in_filename, "r", encoding="utf-8") as f:

            for line in f:
                if line.startswith("anonymous@"):
                    domains += [line.removeprefix("anonymous@").removesuffix("\n")]
                    new_block = True
                    blocks += 1
                    if current_block:
                        if not saw_cert:
                            failed_blocks.append("".join(current_block))
                    current_block = [line]
                    saw_cert = False
                else:
                    # Add line to current block
                    current_block.append(line)
                    if "OpenSSL: saving certificate: " in line:
                        if "depth 0" in previous_line:
                            if line.removeprefix("OpenSSL: saving certificate: ").removesuffix("\n") in cert_names:
                                if new_block:
                                    duplicated_certs += 1

                            cert_names.add(line.removeprefix("OpenSSL: saving certificate: ").removesuffix("\n"))
                            new_block = False

                    if "CTRL-EVENT-EAP-PEER-CERT" in line:
                        saw_cert = True

                    if "EAP-PEAP: Start (server ver=1" in line:
                        ver_1_domains += [domains[-1]]

                previous_line = line

    # Handle the last block
    if current_block and not saw_cert:
        failed_blocks.append("".join(current_block))

    # Write output
    # with open(out_filename, "w", encoding="utf-8") as f:
    #     for block in failed_blocks:
    #         f.write(block + "\n")

    print(f"In duplicated domains: {list((Counter(domains) - Counter(realms)).elements())}")
    #print(f"In duplicated domains: {list((Counter(certfilenames) - Counter(new_cert_names)).elements())}")

    #print(f"Saved certs: {len(set(old_cert_names))}")
    print(f"Saved certs: {len(set(cert_names))}")
    print(f"Done. Found {duplicated_certs} certificate duplicates.")
    print(f"Done. Found {len(failed_blocks)} failures out of {blocks} connection attempts") #and {len(set(domains))} distinct "
         # f"domains.")
    #print(cert_names)
    print(len(ver_1_domains))
    print(ver_1_domains)
    store_file(ver_1_domains, "version0/version1_domains.json")

def find_ver0_only():
    domains = []
    successful_domains = []
    saw_cert = False

    ver_1_domains = json.load(open('version0/version1_domains.json'))


    with open(condensed_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("anonymous@"):
                if saw_cert:
                    successful_domains += [domains[-1]]
                domains += [line.removeprefix("anonymous@").removesuffix("\n")]
                saw_cert = False
            else:
                if "CTRL-EVENT-EAP-PEER-CERT" in line:
                    saw_cert = True
        if saw_cert and len(domains)>0:
            successful_domains += [domains[-1]]

    print(f"In duplicated domains: {len(list((Counter(ver_1_domains) - Counter(successful_domains)).elements()))}")
    print(f"In duplicated domains: {list((Counter(ver_1_domains) - Counter(successful_domains)).elements())}")
    print(len(ver_1_domains))
    print(ver_1_domains)
    print(len(successful_domains))
    print(successful_domains)

condense_file(input_file, condensed_file)
#find_failed_connections(condensed_file, output_file)
#find_ver0_only()


