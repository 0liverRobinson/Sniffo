# Create object to store all the packet information
class sniffData:
    def __init__(this, protocol, source_ip, destination_ip, packet_size, ttl, data):
        this.protocol = protocol
        this.source_ip = source_ip
        this.destination_ip = destination_ip
        this.packet_size = packet_size
        this.ttl = ttl
        this.data = data
        pass