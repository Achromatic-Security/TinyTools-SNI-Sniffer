# Tiny Tools - SNI Sniffer

A simply SNI sniffer which has been wrote as part of the tiny tools series by Achromatic Security

This tool simply listens on a specified interface and passively intercepts SSL/TLS connections and attempts to extract the SNI.

Visit https://www.achromatic-security.com/blog-sni-sniffer for more information on SNIs

## Requirements

Most of the modules used should already be installed by default. However the two you will need to install our:
*Scapy
*Scapy-ssl_tls - Follow the instructions here to install: https://github.com/tintinweb/scapy-ssl_tls

## Usage

usage: sni_sniff.py [-h] -i INTERFACE [-o OUTPUT]

-i specify the interface in which you wish to listen on
-o specify an output file to write to (csv formatted output)
*If the -o is not provided then the results will be written to stdout

