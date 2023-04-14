import argparse

import os

import sys

import signal

import logging

from scapy.all import *

from colorama import init, Fore

import netfilterqueue

import re

logging.basicConfig(level=logging.INFO,

                    format="%(asctime)s %(levelname)s: %(message)s",

                    datefmt="%Y-%m-%d %H:%M:%S")

init()

GREEN = Fore.GREEN

RESET = Fore.RESET

def handle_interrupt(signum, frame):

    logging.info("User interrupt signal received. Exiting...")

    sys.exit(0)

def main():

    parser = argparse.ArgumentParser(description="Interceptor - A network packet interceptor")

    parser.add_argument("-i", "--iface", help="The network interface to listen on")

    parser.add_argument("-a", "--address", help="The IP address of the target host to intercept traffic to/from")

    parser.add_argument("-p", "--port", help="The port number of the target service to intercept traffic to/from")

    args = parser.parse_args()

    if not args.address:

        logging.error("You must specify the target IP address to intercept traffic to/from")

        sys.exit(1)

    if not args.port:

        logging.error("You must specify the target port number to intercept traffic to/from")

        sys.exit(1)

    # Set up the signal handler for user interrupts (Ctrl-C)

    signal.signal(signal.SIGINT, handle_interrupt)

    # Start the interception

    interceptor = Interceptor(args.address, args.port, args.iface)

    interceptor.start()

if __name__ == "__main__":

    main()
