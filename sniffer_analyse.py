from tkinter import ttk
from tkinter import *
import tkinter

class PacketAnalyse:

    def createWindow(this):
        this.win = Tk()
        this.win.title(this.protocol + " Packet #" + this.packetNo)

        this.centreX = str ( int ( 1/2 *  (this.win.winfo_screenwidth() - this.width ) ) )
        this.centreY = str ( int  ( 1/2 *  (this.win.winfo_screenheight() - this.height ) ) )
        this.win.mainloop()

    def _udpeval(this):
        # Source
        # Dest
        # Source Port
        # Destination Port
        # Data (decode)
        pass
    
    def _tcpeval(this):
        pass

    def _icmpeval(this):
        pass

    def analysePacket(this):
        pass



    def __init__(this, packet, packetNo):
        this.width = 100
        this.height = 100
        this.protocol = packet.protocol
        this.data = packet.data
        this.packetNo = packetNo
        this.analysePacket()