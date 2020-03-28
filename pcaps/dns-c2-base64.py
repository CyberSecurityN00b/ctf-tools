#!/usr/bin/env python3
import argparse
import base64
import re
import string
import sys

from scapy.all import *

def DecodeResponse(query):
    ### BEGIN STOLEN CODE ###
    # Stole below from someone on StackOverflow
    def capitalization_permutations(s):
        if s == '':
            yield ''
            return
        for rest in capitalization_permutations(s[1:]):
            yield s[0].upper() + rest
            if s[0].upper() != s[0].lower():
                yield s[0].lower() + rest
    #### END STOLEN CODE ####

    try:query = query.decode()
    except:pass

    padded_query = query + ('=' * (4 - (len(query) % 4)))
    poss_output = []
    for part in map(''.join, zip(*[iter(padded_query)] * 4)):
        part_output=[]
        for perm in capitalization_permutations(part):
            try:
                permx = base64.b64decode(perm).decode(encoding='latin-1')
                if all(c in string.printable for c in permx):
                    part_output.append(permx)
            except:pass
        if len(part_output)==0:
            return []
        poss_output.append(part_output)

    return sorted(list(set([''.join(x) for x in list(itertools.product(*poss_output))])))

def GetDecodedDNSC2ResponsesByDomains(pcap):
    packets = rdpcap(pcap)
    results = {}
    badchars = '\r\n\t\x0b\x0c'

    for p in packets:
        if p.haslayer(DNS) and p.haslayer(DNSRR):
            domain = p[DNS].qd.qname.decode()

            # Add it in if it doesn't exit
            if not domain in results:
                results[domain]=[]

            for i in range (p[DNS].ancount):
                for z in p[DNS].an[i].rdata:
                    results[domain].append(DecodeResponse(z))

    for domain in results.keys():
        if len(results[domain])==0:
            del results[domain]

    return results

# Overload argparse to avoid error message
class CustomParser(argparse.ArgumentParser):
    def error(self,message):
        self.print_help()
        sys.exit(2)

def main():
    ## Build Parser ###########
    parser = CustomParser(description='Decodes base-64 encoded C2 commands sent in DNS replies.')

    # Parser -> pcap
    parser.add_argument('pcap', \
                        metavar = 'pcap', \
                        type = str, \
                        help = 'path to pcap file')

    # Parser -> regex
    parser.add_argument('--regex', \
                        default = '.+', \
                        help = 'only show possibilities matching the regex')

    args = parser.parse_args()

    ## Actual program #########
    domains = GetDecodedDNSC2ResponsesByDomains(args.pcap)
    pattern = re.compile(args.regex)
    for domain in domains.keys():
        print('=' * 80)
        print('DOMAIN: %s' % (domain))
        print('=' * 80)
        responses = domains[domain]
        for qi in range(len(responses)):
            if len(responses[qi])>0:
                output = []
                for pi in range(len(responses[qi])):
                    possibility = responses[qi][pi]
                    match = pattern.search(possibility)
                    if match:
                       output.append(' - Possibility %02d: %s' % (pi,possibility))
                if len(output)>0:
                    print('---------- Query %02d ----------' % (qi))
                    for out in output:print(out)
                    print('')
        print('=' * 80)
        print('')

if __name__ == '__main__':
    main()

