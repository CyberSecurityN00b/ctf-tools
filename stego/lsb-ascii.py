#!/usr/bin/env python3
import argparse
import re
import sys

def ReadLSB(filepath):
    f = open(filepath, 'rb')
    lsb = ''
    output = []

    # Read in the Least Significant Bits
    while True:
        byte = f.read(1)
        if not byte:
            break
        lsb += str(byte[0] & 1)

    # Handle offset (since ascii, only 8 possible)
    for offset in range(8):
        offset_lsb = (offset * '0') + lsb
        text = ''
        # Compress binary string to binary
        for byte in map(''.join, zip(*[iter(offset_lsb)]*8)):
            text += chr(int('0'+byte,2))
        output.append(text)

    return output

def FindFlag(filepath, flag):
    matches = []
    pattern = re.compile(flag)

    for line in ReadLSB(filepath):
        match = pattern.search(line)
        if match:
            matches.append(match.group(0))

    return matches

# Overload argparse to avoid error message
class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        sys.exit(2)

def main():
    ## Build Parser ###########
    parser = CustomParser(description='Find ASCII CTF flag in file\'s Least Significant Bits.')

    # Parser -> Filepath
    parser.add_argument('file', \
                        metavar = 'file', \
                        type = str, 
                        help = 'path to CTF file')

    # Parser -> Flag
    parser.add_argument('--flag', \
                        type = str, \
                        default = 'flag\{[^\}]*\}', \
                        help = 'regex for flag format (default matches \'flag{*}\'')

    args = parser.parse_args()

    ## Actual program #########
    for flag in FindFlag(args.file,args.flag):
        print(flag)

if __name__ == '__main__':
    main()
