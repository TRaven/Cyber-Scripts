# Cyber-Scripts
Here are my personal scripts.

## BulkWhois.py
This is a script that takes a manual comma separated list of IP/Domains or a CSV with a column containing IP/Domains and performs a whois and an alternate OTX search for them.

Simply Run the script and you will be prompted for input. The only change you should have to make in the script itself is input the Alienvault OTX API key from your account near the top.

## crowdstrikeAPIQuery.py
This script will query the Crowdstrike API and dump a csv.

## csv_merge.py
This script will take X amount of CSV files and compare a column between them. It is best if the column to be compared in the secondary one contains unique values so that it more accurately appends the corresponding row data to the primary.

For example: A vuln scan with a column showing IPs as a primary and an asset inventory showing IPs as a secondary. The asset inventory data for each host can be used to enrich the vuln scan data.

## icebrgAPIQuery.py
This script will query iceberg API and dump a csv.
