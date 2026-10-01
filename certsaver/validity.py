#!/usr/bin/env python3
from cryptography import x509
import pem
import seaborn
import os
import pandas as pd
import matplotlib.pyplot as plt

folder = "scrapedcerts/"
directory = os.fsencode(folder)
validity_periods = []
files = os.listdir(directory)


more_than_one_year = 0
more_than_two_years = 0
more_than_ten_years = 0
less_than_three_months = 0
maybe_expired = []
validity_periods_days = []

for file in files:
    filename = os.fsdecode(file)

    certs = pem.parse_file(folder + filename)

    cert = x509.load_pem_x509_certificate(str(certs[0]).encode())
    start_date = cert.not_valid_before_utc
    end_date = cert.not_valid_after_utc
    difference = end_date - start_date
    validity_periods += [difference.days / 365]
    validity_periods_days += [difference.days]



    if difference.days == 1:
        print("hello world")
        print(filename)
        print(end_date)
    if difference.days > 365:
        more_than_one_year += 1
    if difference.days >= 730:
        more_than_two_years += 1
    if difference.days >= 3650:
        more_than_ten_years += 1
    if difference.days <= 90:
        less_than_three_months += 1


print(f"More than one year: {more_than_one_year}")
print(f"At least two years: {more_than_two_years}")
print(f"At least ten years: {more_than_ten_years}")
print(f"Less than three months: {less_than_three_months}")

print(max(validity_periods))
print(max(validity_periods_days))
print(min(validity_periods))
print(min(validity_periods_days))
data = {
  "Validity Period (Years)": validity_periods
}
df = pd.DataFrame(data)
#print(df)
seaborn.ecdfplot(data=df, x="Validity Period (Years)", log_scale=True, legend=False)
plt.savefig("validityperiods.pdf")
