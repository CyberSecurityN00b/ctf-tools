# CTF Tools for PCAP Analysis

  - **dns-c2-base64.py** - Looks for base64 encoded commands in DNS response traffic. Brute-forces upper/lower case for each character in response. Supports regex filtering. (Note: This was written for a CTF where the tool used to grab the pcap made everything lowercase in the DNS responses, which accounts for the brute-force approach.)
