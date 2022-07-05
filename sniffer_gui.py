from threading import Thread
from tkinter import ttk
from tkinter import *
import tkinter

from sniffer_analyse import PacketAnalyse

class Window:
    
    # On double click, open packet window with details
    def analyse( this, wc ):
        
        # Retrieve index in table
        current_row = this.table.selection()
        index = this.table.item(current_row, "values")[0]

        # Retreive data in array
        packet_data = this.packet_details[int ( index ) ]
        
        # Create window to display packet data
        analysisWin = PacketAnalyse(packet_data, index)
        
        # Create new thread and then render a new window to display packet data
        newWinThread = Thread(target=analysisWin.createWindow)
        newWinThread.start()
        

    def createWindow(this):
        
        # Create window
        this.win.title("Sniffo - Packet Sniffer")

        # Find center coordinates for window
        this.centreX = str ( int ( 1/2 *  (this.win.winfo_screenwidth() - this.width ) ) )
        this.centreY = str ( int  ( 1/2 *  (this.win.winfo_screenheight() - this.height ) ) )

        # Place center of screeen
        this.win.geometry( str ( this.width ) + 'x' + str ( this.height ) + '+' + this.centreX + '+' + this.centreY )

        #  Set favicon
        this.win.iconphoto(False, tkinter.PhotoImage(file='img/logo.png'))

        # Set background to black
        this.win.configure(background="black")
        
        # Fill table background in as black
        this.s = ttk.Style(this.win)
        this.s.configure("Treeview", background="black", fieldbackground="black")

        # Create packet sniffing table    
        this.table = ttk.Treeview(this.win, columns=(0,1,2,3,4, 5), show='headings', height=17)

        # Add packet columns
        this.table.column(0, width=70)      # Packet index
        this.table.column(1, width=70)      # Protocol type
        this.table.column(2, width=200)     # Source IP
        this.table.column(3, width=200)     # Destination IP
        this.table.column(4, width=100)     # Packet size
        this.table.column(5, width=60)      # Time to live
        
        # Add packet headings
        this.table.heading(0, text="Index")             # Packet index
        this.table.heading(1, text="Protocol")          # Protocol
        this.table.heading(2, text="Source IP")         # Source IP
        this.table.heading(3, text="Destination IP")    # Destination IP
        this.table.heading(4, text="Packet size")       # Packet size
        this.table.heading(5, text="TTL")               # Time to live

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

        # Create event listener for double clicking on row to open window with packet details
        this.table.bind( "<Double-1>", this.analyse )

        # Create bottom frame for the toggle buttons
        this.bottomFrame = Frame(this.win)
        this.bottomFrame.pack(side=BOTTOM, fill=BOTH)
        
        # Create buttons:   
        this.start_button = Button(this.bottomFrame, text="Start", command=this.thread.start)
        this.start_button.pack(side=LEFT)
        
        # Create filters for incoming packets (not past packets)
        this.UDPFiler = BooleanVar()
        this.ICMPFilter = BooleanVar()
        this.TCPFilter = BooleanVar()

        # Automatically disable all filters and display them as checkboxes
        this.UDPCheck = ttk.Checkbutton(this.bottomFrame, text="UDP", variable=this.UDPFiler, onvalue=False, offvalue=True)         # UDP Filter
        this.TCPCheck = ttk.Checkbutton(this.bottomFrame, text="TCP", variable=this.TCPFilter, onvalue=False, offvalue=True)        # TCP Filter
        this.ICMPCheck = ttk.Checkbutton(this.bottomFrame, text="ICMP", variable=this.ICMPFilter, onvalue=False, offvalue=True)     # ICMP Filter

        # Place filter checkboxes to window
        this.UDPCheck.pack(side=LEFT)
        this.TCPCheck.pack(side=LEFT)
        this.ICMPCheck.pack(side=LEFT)

        
    
    def __init__(this, width, height, thread) -> None:
        
        # Number of packets is 0
        this.dataCount = 0

        # Set window height and width
        this.width = width
        this.height = height

        # Thread to start sniffing packets
        this.thread = thread
        this.isThreadActive = False

        # Initialise filter values to None
        this.UDPFiler = None
        this.ICMPFilter = None
        this.TCPFilter = None

        # Create array for storing packet data
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
        
        # Insert data into table and increment data count
        this.table.insert(parent='', index=this.dataCount, values=(this.dataCount, sniffRes.protocol, sniffRes.source_ip, sniffRes.destination_ip, sniffRes.packet_size, sniffRes.ttl), tags=sniffRes.protocol)
        this.packet_details.append(sniffRes)
        this.dataCount+=1

        # Auto scroll
        if ( this.sb.get()[1]  == 1 ):
            this.table.yview_moveto(1)
        pass