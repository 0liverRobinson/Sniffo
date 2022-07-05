# I really feel this applicaiton is just an attempt to put the word "sniff" in as much places as possible :) #

import multiprocessing
import struct
import socket
import sys
from threading import Thread
import time

from sniffer_gui import Window
from sniff_res import sniffData

# Display results on a window
def displaySniffing():

    # Create new window
    window = Window(715, 400, sniff_thread)
    try: 
        while True:
                # Dump results to table and update window
                while len ( sniffresults ) > 0:

                    # Add data to window table
                    window.insert(sniffresults.pop(0))

                    # Update window when adding items to tables
                    window.win.update()
                    window.win.update_idletasks()

                # Update window after every loop
                window.win.update()
                window.win.update_idletasks()
    except:
        # Exit program
        sys.exit()
        
    pass

# Sniff packets
def sniff():

    # Create socket for packet sniffing
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:

        # Recieve packet
        packet_data = sock.recvfrom(MAX_PACKET_SIZE)[0]

        # Extract IP Addresses
        source_address, destination_address = struct.unpack("!4s4s", packet_data[26:34])
        source_address = socket.inet_ntoa(source_address)
        destination_address = socket.inet_ntoa(destination_address)

        # Extract TTL + Protocol
        ip_packet = packet_data[14:]
        ttl, protocol = struct.unpack( "!BB", ip_packet[8:10]  )

        # Get protocol string , else say "no support"
        protocol = protocolToString.get( protocol, "no_support" )

        # Get starting point of packet data
        startofdata = 16

        # if we come across any anonalies or the protocol has no support, continue
        if source_address == "0.0.0.0" or destination_address == "255.255.255.255" or protocol == "no_support":
            continue
        
        # Create instance of sniffData obj with data
        results = sniffData(protocol, source_address, destination_address, str ( len(packet_data ) ), ttl ,ip_packet[startofdata:] )

        # Append results to list
        sniffresults.append(results)
        
    pass



if __name__ == "__main__":
    
    # Set max packet size
    MAX_PACKET_SIZE = 65535
    
    # Create list to store packet data inside
    sniffresults = []

    # Protocl to string translation table
    protocolToString = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    # Create for sniffing packets
    sniff_thread = Thread( target=sniff, daemon=True )

    # Display the data to the window
    displaySniffing()
    
    pass
