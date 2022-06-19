from os import uname
from tkinter import ttk
from tkinter import *
import tkinter
import struct

ECHO_REQUEST = 0
ECHO_RESPONSE = 8

class PacketAnalyse:

    def createWindow(this):
        this.win = Tk() 
        this.win.title(this.protocol + " Packet #" + this.packetNo) 
        this.centreX = str ( int ( 1/2 *  (this.win.winfo_screenwidth() - this.width ) ) )
        this.centreY = str ( int  ( 1/2 *  (this.win.winfo_screenheight() - this.height ) ) )
        this.win.geometry( str ( 400 ) + 'x' + str ( 410 ) + '+' + this.centreX + '+' + this.centreY )
        this.addr_table = ttk.Treeview( this.win, columns=('SRC ADDR', 'DEST ADDR'), show='headings' )

        this.win.resizable(False, False)

        this.addr_table.heading('SRC ADDR', text='Source Address')
        this.addr_table.heading('DEST ADDR', text='Destination Address')

        this.addr_table.insert(parent="", index=1, values=( this.packet.source_ip, this.packet.destination_ip ) )

        this.addr_table.place(x=0,y=0, height=41, width=400)

        
        this.data_table_y=82

        if this.protocol == "TCP":
            this._tcpeval()
        elif this.protocol == "UDP":    
            this._udpeval()
        else:
            this._icmpeval()

        # Format the data:
        data_string = this.data.replace("\\", " ")

        this.data_s = tkinter.Text(this.win, wrap=WORD)
        this.data_s.insert(END, data_string)
        this.data_s.place(x=0,y=this.data_table_y, width=400)
        this.win.mainloop()


    def _udpeval(this):


        source_port = struct.unpack( "!H", this.packet.data[4:6])
        destination_port = struct.unpack("!H", this.packet.data[6:8])
        length = struct.unpack("!H", this.packet.data[8:10])
        checksum = struct.unpack("!H", this.packet.data[10:12])
        this.data = str ( this.packet.data[12:] )


        this.port_table = ttk.Treeview( this.win, columns=('SRC PORT', 'DEST PORT'), show='headings' )

        this.port_table.heading('SRC PORT', text='SRC PORT')
        this.port_table.heading('DEST PORT', text='DEST PORT')

        

        this.port_table.insert(parent="", index=1, values=(source_port, destination_port))

        this.port_table.place(x=0, y=41, width=400, height=41)
        pass
    
    def _tcpeval(this):


        source_port = struct.unpack( "!H", this.packet.data[4:6])
        destination_port = struct.unpack("!H", this.packet.data[6:8])


        seq_no,ack,orf = struct.unpack("!LL H", this.packet.data[8:18])


        data_offset = (struct.unpack("!H", this.packet.data[16:18])[0] >>12) *4 
        this.data = str ( this.packet.data[data_offset:] )

        this.port_table = ttk.Treeview( this.win, columns=('SRC PORT', 'DEST PORT'), show='headings' )

        this.port_table.heading('SRC PORT', text='SRC PORT')
        this.port_table.heading('DEST PORT', text='DEST PORT')



        this.port_table.insert(parent="", index=1, values=(source_port, destination_port))

        this.port_table.place(x=0, y=41, width=400, height=41)


        pass

    def _icmpeval(this):
        this.data_table_y=41
        echo_code = ECHO_REQUEST if struct.unpack( "!h", this.packet.data[4:6])[0] == 2048 else ECHO_RESPONSE
        echo_string = "Echo Request [0]" if echo_code == ECHO_REQUEST else "Echo Response [8]"
        this.data = echo_string + "\n" + str ( this.packet.data[8:] )


    def __init__(this, packet, packetNo):
        this.width = 100
        this.height = 100
        this.packet = packet
        this.protocol = packet.protocol
        this.data = packet.data
        this.packetNo = packetNo