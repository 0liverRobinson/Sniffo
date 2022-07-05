from os import uname
from tkinter import ttk
from tkinter import *
import tkinter
import struct

ECHO_REQUEST = 0
ECHO_RESPONSE = 8

class PacketAnalyse:

    def createWindow(this):
        
        # New window
        this.win = Tk() 
        this.win.title(this.protocol + " Packet #" + this.packetNo) 
        
        # Center window on screen
        this.centreX = str ( int ( 1/2 *  (this.win.winfo_screenwidth() - this.width ) ) )
        this.centreY = str ( int  ( 1/2 *  (this.win.winfo_screenheight() - this.height ) ) )
        this.win.geometry( str ( 400 ) + 'x' + str ( 410 ) + '+' + this.centreX + '+' + this.centreY )
        
        # Create address table
        this.addr_table = ttk.Treeview( this.win, columns=('SRC ADDR', 'DEST ADDR'), show='headings' )
        
        # Make window size constant
        this.win.resizable(False, False)
        
        # Add Address table headings
        this.addr_table.heading('SRC ADDR', text='Source Address')
        this.addr_table.heading('DEST ADDR', text='Destination Address')
        
        # Address addresses to address table
        this.addr_table.insert(parent="", index=1, values=( this.packet.source_ip, this.packet.destination_ip ) )

        # Place address table into window
        this.addr_table.place(x=0,y=0, height=41, width=400)

        # Place data table in window
        this.data_table_y=82

        # Analyse the packet
        if this.protocol == "TCP":  
            this._tcpeval()
        elif this.protocol == "UDP":    
            this._udpeval()
        else:
            this._icmpeval()

        # Format the data:
        data_string = this.data.replace("\\", " ")
        
        # Display packet data: 
        this.data_s = tkinter.Text(this.win, wrap=WORD)
        this.data_s.insert(END, data_string)
        
        # Place text area with data in window
        this.data_s.place(x=0,y=this.data_table_y, width=400)
        
        # Refresh window
        this.win.mainloop()

    # Evaluate UDP Packet
    def _udpeval(this):
        
        # Extract source port
        source_port = struct.unpack( "!H", this.packet.data[4:6])
        
        # Extract desintation port
        destination_port = struct.unpack("!H", this.packet.data[6:8])
        
        # Extract packet length
        length = struct.unpack("!H", this.packet.data[8:10])
        
        # Extract the checksum
        checksum = struct.unpack("!H", this.packet.data[10:12])
        
        # Extract the actual packet data
        this.data = str ( this.packet.data[12:] )

        # Create port table
        this.port_table = ttk.Treeview( this.win, columns=('SRC PORT', 'DEST PORT'), show='headings' )
        
        # Create port table headings
        this.port_table.heading('SRC PORT', text='SRC PORT')
        this.port_table.heading('DEST PORT', text='DEST PORT')

        # Insert data in port table
        this.port_table.insert(parent="", index=1, values=(source_port, destination_port))
        
        # Place port table in window
        this.port_table.place(x=0, y=41, width=400, height=41)
        
        pass
    
    # Evaluate TCP Packet
    def _tcpeval(this):

        # Extract the source port
        source_port = struct.unpack( "!H", this.packet.data[4:6])

        # Extract destination port
        destination_port = struct.unpack("!H", this.packet.data[6:8])

        # Extract the actual data 
        data_offset = (struct.unpack("!H", this.packet.data[16:18])[0] >>12) *4 
        this.data = str ( this.packet.data[data_offset:] )

        # Create port table
        this.port_table = ttk.Treeview( this.win, columns=('SRC PORT', 'DEST PORT'), show='headings' )

        # Create port table headings
        this.port_table.heading('SRC PORT', text='SRC PORT')
        this.port_table.heading('DEST PORT', text='DEST PORT')

        # insert values into port table
        this.port_table.insert(parent="", index=1, values=(source_port, destination_port))

        # Place port table
        this.port_table.place(x=0, y=41, width=400, height=41)

        pass
    
    # Evaluate ICMP Packet
    def _icmpeval(this):
        
        # Set data table y position
        this.data_table_y=41

        # Determine the type of ICMP request 
        echo_code = ECHO_REQUEST if struct.unpack( "!h", this.packet.data[4:6])[0] == 2048 else ECHO_RESPONSE
        echo_string = "Echo Request [0]" if echo_code == ECHO_REQUEST else "Echo Response [8]"

        # Extract ICMP packet data
        this.data = echo_string + "\n" + str ( this.packet.data[8:] )

        pass


    def __init__(this, packet, packetNo):
        this.width = 100
        this.height = 100
        this.packet = packet
        this.protocol = packet.protocol
        this.data = packet.data
        this.packetNo = packetNo