# I really feel this applicaiton is just an attempt to put the word "sniff" in as much places as possible :) #

import multiprocessing
import struct
import socket
import sys
from threading import Thread
import time

from sniffer_gui import Window
from sniff_res import sniffData

def displaySniffing():

    # Create new window
    window = Window(715, 400, sniff_thread)
    try: 
        while True:
                # Dump results to table and update window
                while len ( sniffresults ) > 0:
                    window.insert(sniffresults.pop(0))
                    # Update window 
                    window.win.update()
                    window.win.update_idletasks()

                # Update window 
                window.win.update()
                window.win.update_idletasks()
    except:
        # Exit program
        sys.exit()
        

    pass



def sniff():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:

        # Recieve packet
        packet_data = sock.recvfrom(MAX_PACKET_SIZE)[0]

        # Extract IP Addresses
        source_address, destination_address = struct.unpack("!4s4s", packet_data[26:34])
        source_address = socket.inet_ntoa(source_address)
        destination_address = socket.inet_ntoa(destination_address)

        # Extract TTL + Protocol
        ip_packet = packet_data[14:len( packet_data )]
        ttl, protocol = struct.unpack( "!BB", ip_packet[8:10]  )

        protocol = protocolToString.get( protocol, "no_support" )

        if source_address == "0.0.0.0" or destination_address == "255.255.255.255" or protocol == "no_support":
            continue
        
        results = sniffData(protocol, source_address, destination_address, str ( len(packet_data ) ), ttl )
        sniffresults.append(results)
        
    pass



if __name__ == "__main__":
    MAX_PACKET_SIZE = 65535
    sniffresults = []
    protocolToString = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    sniff_thread = Thread( target=sniff, daemon=True )

    displaySniffing()
    pass