input_file = "version0/condensed_file.log"


succeeded_blocks = []
current_block = []
saw_cert = False
ocsp_stapling_succeeded = False
prev_line = ""
all_ocsp_successes = []
successful_connections = []
with open(input_file, "r", encoding="utf-8") as fi:

        for line in fi:
            if line.startswith("anonymous@"):
                if current_block and saw_cert:
                    succeeded_blocks.append("".join(current_block))
                    if ocsp_stapling_succeeded:
                        all_ocsp_successes += [prev_line]
                    successful_connections += [prev_line.strip("\n")]
                current_block = [line]
                ocsp_stapling_succeeded = False
                saw_cert = False
                prev_line = line
            else:
                # Add line to current block
                current_block.append(line)
                if "CTRL-EVENT-EAP-PEER-CERT" in line:
                    saw_cert = True
                if "OCSP response verification succeeded" in line:
                    ocsp_stapling_succeeded = True

# Handle the last block
if current_block and saw_cert:
    succeeded_blocks.append("".join(current_block))
    if ocsp_stapling_succeeded:
        all_ocsp_successes += [prev_line]
    successful_connections += [prev_line.strip("\n")]
#return succeeded_blocks


print(all_ocsp_successes)
print(len(all_ocsp_successes))
print(successful_connections)
print(len(successful_connections))
# Write output
#with open(output_file, "w", encoding="utf-8") as f:
#    for block in all_succeeded_blocks:
#        f.write(block + "\n")


