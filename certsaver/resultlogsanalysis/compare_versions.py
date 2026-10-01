from collections import Counter

folder0 = "scrapedcerts/"
folder1 = "scrapedcerts/"

session0 = "version0/condensed_file.log"
session1 = "version1/condensed_file.log"

def find_success_realms(in_filename):
    saw_cert = False
    new_block = True
    realm = ""
    success_realms = {}
    #cert_names = []
    previous_line = ""

    with open(in_filename, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("anonymous@"):
                    # if len(realm) > 0:
                        # if saw_cert:
                            # success_realms[realm] = []
                    # saw_cert = False
                    new_block = True
                    realm = line.removeprefix("anonymous@").removesuffix("\n")
                else:
                    if "OpenSSL: saving certificate: " in line:
                        if "depth 0" in previous_line:
                            if new_block:
                                if not realm in success_realms:
                                    success_realms[realm] = [line.removeprefix("OpenSSL: saving certificate: ").removesuffix("\n")]
                                else:
                                    success_realms[realm] += [line.removeprefix("OpenSSL: saving certificate: ").removesuffix("\n")]
                                new_block = False
                    # if "CTRL-EVENT-EAP-PEER-CERT" in line:
                    #     saw_cert = True
                previous_line = line

            if len(realm) > 0:
                if saw_cert:
                    success_realms += [realm]
            return success_realms



realms0 = find_success_realms(session0)
realms1 = find_success_realms(session1)

print(len(realms0))
print(len(realms1))

both_success_realms = set((Counter(list(realms0.keys())) & Counter(list(realms1.keys()))).elements())
print(len(both_success_realms))

realms0_two_successes = {k: v for k, v in realms0.items() if k in both_success_realms}
print(f"realms0 also successful in realms1: {len(realms0_two_successes)}" )
realms1_two_successes = {k: v for k, v in realms1.items() if k in both_success_realms}
print(f"realms1 also successful in realms0: {len(realms1_two_successes)}" )

print(f"same dict? {realms0_two_successes == realms1_two_successes}")
#print(realms0_two_successes)
#print(realms1_two_successes)

all_diff = {
    k: (realms0_two_successes.get(k), realms1_two_successes.get(k))
    for k in realms0_two_successes.keys() | realms1_two_successes.keys()
    if realms0_two_successes.get(k) != realms1_two_successes.get(k)
}

print(all_diff)




with open(session0, "r", encoding="utf-8") as f:
    realm = ""
    for line in f:
        if line.startswith("anonymous@"):
            realm = line.removeprefix("anonymous@").removesuffix("\n")
        else:
            if "OCSP response verification succeeded" in line:
                if realm in both_success_realms:
                    print(f"success in both realms: {realm}")



# Different certs? 'lhsc.on.ca', buas.nl
# osu.edu 2026-05-29
# iadt.ie 2026-11-28
# ku.ac.ae  2026-04-15
# dzne.de 2026-04-04
# sciencespobordeaux.fr 2026-06-19
# dshsserver.dshs-koeln.de 2027-01-12
# 'hereon.de' Expires: 2026-10-13
# ensae.fr 2026-04-11
