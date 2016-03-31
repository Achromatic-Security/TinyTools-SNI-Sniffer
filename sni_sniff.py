try:
	import logging
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import *
	from scapy.layers.ssl_tls import *
	import sys,datetime,argparse,csv,base64,re
except:
	print """Failed to import the required modules for this to work, please ensure you have the following installed before use
[+]Scapy
[+]Scapy SSL_TLS (https://github.com/tintinweb/scapy-ssl_tls)
Also ensure you are running the script as root! :-)\n"""
	import sys
	sys.exit(1)

# Dictionary of SSL/TLS handshake record type values
ssl_handshake_record_type = {
22:"Handshake",
20:"Change Cipher Spec",
21:"Alert",
23:"Application Data"
}

# Dictionary of SSL/TLS handshake type values
ssl_handshake_type = {
0:"HELLO_REQUEST",
1:"CLIENT_HELLO",
2:"SERVER_HELLO",
11:"CERTIFICATE",
12:"SERVER_KEY_EXCHANGE",
13:"CERTIFICATE_REQUST",
14:"SERVER_DONE",
15:"CERTIFICATE_VERIFY",
16:"CLIENT_KEY_EXCHANGE",
20:"FINISHED" 
}

def dissect_packet(pkt,rtype,ssl_hs_type):
        global output_file
        if ssl_hs_type == 1:
                sni = str(pkt[SSL].records[0].payload[TLSExtServerNameIndication].server_names[0].data)
                packet_date = str(datetime.datetime.fromtimestamp(int(pkt.time)).strftime('%Y-%m-%d %H:%M:%S'))
                source_address = str(pkt[IP].src)
                source_port = str(pkt[TCP].sport)
                remote_address = str(pkt[IP].dst)
                remote_port = str(pkt[TCP].dport)
                if output_file != 0:
                        file = open(output_file,'a')
                        writer = csv.writer(file)
                        writer.writerow((packet_date,source_address,source_port,sni,remote_address,remote_port))
                        file.close()
                else:
                        print """
******************************************************
Date/Time Request was made: %s
Source Address: %s
Source Port: %s
SNI: %s
Remote Address: %s
Remote Port: %s
******************************************************"""%(packet_date,source_address,source_port,sni,remote_address,remote_port)

def pkt_callback(pkt):
        if pkt.haslayer(SSL):
                try:
                    content_type = pkt[SSL].records[0].content_type
                    ssl_hs_type = pkt[SSL].records[0].payload.type
                    dissect_packet(pkt,content_type,ssl_hs_type)
                except:
                	pass                      
                        

def main(interface):
        try:
                bind_layers(TCP, SSL)
                bind_layers(UDP, SSL)
                sniff(iface=interface, prn=pkt_callback, store=0)
        except Exception,err:
                print "\n\n*** Problem encountered whilst attemting to listen on the interface: %s ***\n\nCheck you are root or that the interface exists!"%interface
                sys.exit(0)

if __name__ == '__main__':
        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="""
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
""")
        parser.add_argument('-i','--interface',required=True,help='Specify the interface in which to listen on e.g eth0')
        parser.add_argument('-o','--output',required=False,help='File to log all requests to (requests will be displayed in stdout if not specified)')
        args = vars(parser.parse_args())
        if args["output"]:
                output_file = args['output']
		print "Monitoring SNIs and writing them out to a file called: %s"%output_file
        else:
                output_file = 0
        main(args["interface"])
