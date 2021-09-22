#!/usr/bin/python
# Simple IDS for the Raspberry Pi
# Whitelisted IPs eg: ["123.123.123.123", "1.2.3.4"]
whitelist = [""]
# Logfile location (leave blank for no file logging)
logfile = "/var/log/Pids.log"
# Response string that is sent to the connecting client (ie "Go Away!")
response = "Go Away!"
# Path to response script that gets run upon client connection and returns a string to be sent back
# This script will be executed by Python and will be passed the client IP as a parameter
# If this is set, it will override the response string set above.
response_script = ""
# ----CONFIG END-------------------------------------------------

# Imports

import logging  # To write logs
import os  # Import os because on Linux to run commands I had to use popen
import platform  # Import platform module to determine the os
import socket  # Import socket module
import sys  # Import sys and getopt to grab some cmd options like port number
from subprocess import CalledProcessError, \
    check_output  # Import module for making OS commands (os.system is deprecated)


# if exists('/etc/whilelists'):
with open('/etc/whitelists', 'r') as f:
    whitelisted = f.read().split('\n')

bind_ip = '0.0.0.0'
port = 31337
# whitelist = []

platform = platform.system()  # Get the current platform (Linux, Darwin, Windows)
#
# Check for root
if platform == "Linux" or platform == "Darwin":  # If Unix or Darwin
    if not os.geteuid() == 0:
        sys.exit("\n[!] Root privileges are required to modify firewall rules.\n")

# If using Dome9, check API username/key are set - or die.
# TODO validate they work

# Check port number is valid and can be bound - or die.
if 1 <= port <= 65535:
    try:
        s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_socket.bind(("0.0.0.0", port))
    except socket.error as e:
        sys.exit("[!] Unable to bind to port with error: {0} -- {1} ".format(e[0], e[1]))
else:
    print("[!] Please specify a valid port range (1-65535) in the configuration.")
    sys.exit(2)
#
# Initiate logger
logger = logging.getLogger(__name__)
formatter = logging.Formatter("%(message)s - %(asctime)s", "%c")
strmhndlr = logging.StreamHandler()
logger.addHandler(strmhndlr)
strmhndlr.setFormatter(formatter)
if logfile != "":  # If a logfile name is set, add it to the logger
    try:
        fihndlr = logging.FileHandler(logfile)
        fihndlr.setFormatter(formatter)
        logger.addHandler(fihndlr)
    except IOError as e:
        sys.exit("[!] Unable to create/append logfile: {0} -- {1} ".format(e[0], e[1]))
logger.setLevel(logging.INFO)
logger.propagate = True
#
# Start listening
s_socket.listen(5)
host_ip = s_socket.getsockname()[0]
logger.info("[*] Starting IDS listener on port" + " " + str(port) + " Waiting for the intruders...".format(port))
#
while True:
    c, addr = s_socket.accept()  # Accept connection
    client_ip = str(addr[0])  # Get client IP
    print(whitelisted)
    if client_ip in whitelisted or client_ip in ("127.0.0.1", "192.168.1.24", "192.168.1.18"):
        logger.info(
            "[+] intrusion in network from Whitelist IP  : {0} with IPTABLES (TTL: {1})".format(client_ip, "Permanent"))
        logger.info("[!] intrusion in network from Whitelist IP  in port : " + str(port) + " ".format(client_ip))
    else:
        # Send response to client
        if response_script == "":
            if sys.version_info < (3, 0):
                c.sendall(response)
            else:
                c.sendall(bytes(response, 'UTF-8'))
        else:
            res = check_output(["python", response_script, client_ip])
            if sys.version_info < (3, 0):
                c.sendall(res)
            else:
                c.sendall(bytes(res, 'UTF-8'))
        #
        # Close the client connection, don't need it any more.
        #   c.shutdown(socket.SHUT_RDWR)
        c.close()

        if platform == "Linux":  # use Linux IPtables
            try:
                result = check_output(
                    ["/sbin/iptables", "-A", "INPUT", "-s", "{0}".format(client_ip), "-j", "DROP"])
                logger.info(
                    "[!] intrusion in network from external IP in port : " + str(port) + " ".format(client_ip))
                logger.info("[+] Blacklisting: {0} with IPTABLES (TTL: {1})".format(client_ip, "Permanent"))
            except (OSError, CalledProcessError) as e:
                logger.error(
                    "[!] Failed to blacklist {0} with IPTABLES ({1}), is iptables on the PATH?".format(client_ip,
                                                                                                       e))
