from threading import Thread
from tkinter import ttk
from tkinter import *
import tkinter

from matplotlib.pyplot import table
from sniffer_analyse import PacketAnalyse

class Window:

    def analyse( this, wc ):
        
        # Retrieve index in table
        aa = this.table.selection()
        index = this.table.item(aa, "values")[0]

        # Retreive data in array
        packet_data = this.packet_details[int ( index ) ]

        analysisWin = PacketAnalyse(packet_data, index)
        
        newWinThread = Thread(target=analysisWin.createWindow)
        newWinThread.start()

        # Open window with data: 
        print ( packet_data.source_ip) 
        print ( packet_data.destination_ip) 
        print ( packet_data.packet_size) 
        print ( packet_data.ttl )
        

    def createWindow(this):
        
        # Create window
        this.win.title("Sniffo - Packet Sniffer")
        this.centreX = str ( int ( 1/2 *  (this.win.winfo_screenwidth() - this.width ) ) )
        this.centreY = str ( int  ( 1/2 *  (this.win.winfo_screenheight() - this.height ) ) )
        this.win.geometry( str ( this.width ) + 'x' + str ( this.height ) + '+' + this.centreX + '+' + this.centreY )
        this.win.iconphoto(False, tkinter.PhotoImage(file='img/logo.png'))
        this.win.configure(background="black")
        
        # Fill table background in as black
        this.s = ttk.Style(this.win)
        this.s.configure("Treeview", background="black", fieldbackground="black")

        # Create table        
        this.table = ttk.Treeview(this.win, columns=(0,1,2,3,4, 5), show='headings', height=17)
        this.table.column(0, width=70)
        this.table.column(1, width=70)
        this.table.column(2, width=200)
        this.table.column(3, width=200)
        this.table.column(4, width=100)
        this.table.column(5, width=60)
        
        this.table.heading(0, text="Index")
        this.table.heading(1, text="Protocol")
        this.table.heading(2, text="Source IP")
        this.table.heading(3, text="Destination IP")
        this.table.heading(4, text="Packet size")
        this.table.heading(5, text="TTL")

        # Create scroll bar
        this.sb = ttk.Scrollbar(this.win, orient='vertical')
        this.table.configure(yscrollcommand=this.sb.set, padding=0)
        this.sb.configure(command=this.table.yview)
        this.sb.pack(side=RIGHT, fill=BOTH)
    
        # Colour code based on protocol
        this.table.tag_configure("ICMP", background="red", font="white", foreground="white")
        this.table.tag_configure("TCP", background="blue", font="white", foreground="white")
        this.table.tag_configure("UDP", background="black", font="white", foreground="yellow")
        
        this.table.pack(side=TOP, fill=BOTH, expand=True)

        # Create event listener for double clicking on row ...
        this.table.bind( "<Double-1>", this.analyse )

        this.bottomFrame = Frame(this.win)
        this.bottomFrame.pack(side=BOTTOM, fill=BOTH)
        
        # Create buttons:   
        this.start_button = Button(this.bottomFrame, text="Start", command=this.thread.start)
        this.start_button.pack(side=LEFT)

        this.UDPFiler = BooleanVar()
        this.ICMPFilter = BooleanVar()
        this.TCPFilter = BooleanVar()

        this.UDPCheck = ttk.Checkbutton(this.bottomFrame, text="UDP", variable=this.UDPFiler, onvalue=False, offvalue=True)
        this.TCPCheck = ttk.Checkbutton(this.bottomFrame, text="TCP", variable=this.TCPFilter, onvalue=False, offvalue=True)
        this.ICMPCheck = ttk.Checkbutton(this.bottomFrame, text="ICMP", variable=this.ICMPFilter, onvalue=False, offvalue=True)
        this.UDPCheck.pack(side=LEFT)
        this.TCPCheck.pack(side=LEFT)
        this.ICMPCheck.pack(side=LEFT)

        
    
    def __init__(this, width, height, thread) -> None:

        this.dataCount = 0
        this.width = width
        this.height = height
        this.thread = thread
        this.isThreadActive = False
        this.UDPFiler = None
        this.ICMPFilter = None
        this.TCPFilter = None
        this.packet_details = []
        
        # Create window    
        this.win = Tk()
        this.createWindow()

        pass

    # Insert data into the table
    def insert(this, sniffRes):

        # Filter packets
        if sniffRes.protocol == "UDP" and this.UDPFiler.get() or sniffRes.protocol == "TCP" and this.TCPFilter.get() or sniffRes.protocol == "ICMP" and this.ICMPFilter.get():
            return
        
        # Insert data into table
        this.table.insert(parent='', index=this.dataCount, values=(this.dataCount, sniffRes.protocol, sniffRes.source_ip, sniffRes.destination_ip, sniffRes.packet_size, sniffRes.ttl), tags=sniffRes.protocol)
        this.packet_details.append(sniffRes)
        this.dataCount+=1

        # Auto scroll
        if ( this.sb.get()[1]  == 1 ):
            this.table.yview_moveto(1)
        pass