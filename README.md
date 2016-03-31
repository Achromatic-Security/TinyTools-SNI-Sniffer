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

 (        )  (      (        )  (    (     (          (     
 )\ )  ( /(  )\ )   )\ )  ( /(  )\ ) )\ )  )\ )       )\ )  
(()/(  )\())(()/(  (()/(  )\())(()/((()/( (()/(  (   (()/(  
 /(_))((_)\  /(_))  /(_))((_)\  /(_))/(_)) /(_)) )\   /(_)) 
(_))   _((_)(_))   (_))   _((_)(_)) (_))_|(_))_|((_) (_))   
/ __| | \| ||_ _|  / __| | \| ||_ _|| |_  | |_  | __|| _ \  
\__ \ | .` | | |   \__ \ | .` | | | | __| | __| | _| |   /  
|___/ |_|\_||___|  |___/ |_|\_||___||_|   |_|   |___||_|_\  
                                                                                                            
SNI Sniffer 0.1 TinyTool by Achromatic Security UK
visit https://www.achromatic-security.com/tools for more details.
Thanks.

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Specify the interface in which to listen on e.g eth0
  -o OUTPUT, --output OUTPUT
                        File to log all requests to (requests will be
                        displayed in stdout if not specified)


