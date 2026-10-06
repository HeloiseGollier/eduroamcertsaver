This repository contains a tool to iteratively collect certificates from Eduroam institutions by connecting to an eduroam network with a list of different realms. This tool was developed in the context of the paper *Looking through the PEAPhole: Security Analysis of PEAP in Eduroam and Enterprise Wi-Fi* to be published at NDSS 2027.

**Experiment:** Collecting Eduroam certificates to check their validity periods. <br>
**Requirements:** A Wi-Fi dongle, being in proximity of an Eduroam network.

Then, compile the modified version of wpa_supplicant, which will save certificates:

    cd wpa_supplicant
    make clean
    make -j 4

Finally, we save the certificates:

    cd ../certsaver
    sudo ./scraper.py your-dongle-id

The certificates we saved are in the directory *scrapedcerts*. We can plot the collected data:
    
    python3 -m venv venv
    source venv/bin/activate
    python3 -m pip install -r requirements.txt
    python3 validity.py
