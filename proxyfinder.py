#!/usr/bin/env python3
import time
from socket import *
from netaddr import IPNetwork
from colorama import Fore, Style
import random, os, pause, sys, re
import os.path
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
bold = Style.BRIGHT
reset = Style.RESET_ALL

home = os.path.dirname(os.path.abspath(__file__))
work = home + '\\'
pfile = work + 'proxy-available.txt'
pfile2 = work + 'proxy-suspicious.txt'
def scan(network):
    hcount = 0
    hosts = IPNetwork(network)
    print("[{}{}{}{}]: {}{}{}{} available IPs".format(bold, blue, network, reset, bold, green, len(hosts), reset), flush=True)
    for host in map(str, hosts):
        print("Scanning: [{}{}{}{}]".format(bold, yellow, host, reset), end="\r", flush=True)
        target(host)
        hcount += 1
        sys.stdout.flush()

def target(ip):
    pports = [80, 81, 83, 88, 443, 3128, 3129, 3654, 4444, 5800, 6588, 6666,
              6800, 7004, 8080, 8081, 8082, 8083, 8088, 8118, 8123, 8888,
              9000, 8084, 8085, 9999, 45454, 45554, 53281]
    for port in pports:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.08)
        result = s.connect_ex((ip, port))
        if result == 0:
            print("", flush=True)
            print("\n{}{}{}{}:{} [{}{}OPEN{}]".format(bold, yellow, ip, reset, port, bold, green, reset), flush=True)
            message = bytes("GET / HTTP/1.1\r\n\r\n", 'utf-8')
            s.sendall(message)
            s.settimeout(0.08)
            try:
                reply = s.recv(100)
                data = reply.decode(encoding='utf-8')
                p = re.compile("Server: (.*)/")
                service = p.search(data)
            except Exception:
                pass
            try:
                if service.group(1) == 'squid':
                    stype = service.group(1)
                    print("Service: [{}{}{}{}]".format(bold, green, str(stype).capitalize(), reset))
                    with open(pfile, 'a+') as pf2:
                        pf2.write("[" + stype.upper() + "] - http " + str(ip) + ":" + str(port) + "\n")
                else:
                    try:
                        from prox_check import is_prox
                        p_str = "http://" + str(ip) + ":" + str(port)
                        prox = is_prox(p_str)
                        if prox == 'socks':
                            print("Service: [{}{}{}{}]".format(bold, green, prox.capitalize(), reset))
                            with open(pfile, 'a+') as pf3:
                                pf3.write("[" + stype.upper() + "] - http " + str(ip) + ":" + str(port) + "\n")
                        else:
                            with open(pfile2, 'a+') as pf4:
                                pf4.write("[-] - http " + str(ip) + ":" + str(port) + "\n")
                            pass
                    except Exception as e:
                        print(str(e))     
            except (NameError, AttributeError) as e:
                print("[{}{}No Proxy{}]\nSkipping..\n".format(bold, red,  reset), flush=True)
        else:
            pass
        s.close()

if __name__ == '__main__':

    with open('ip-list.txt', 'r') as f:
        subnets = f.readlines()

        netlist = []
        num_ips = len(subnets)
        rand_ip = -1
        while len(netlist) < num_ips:
            try:
                netlist.append(subnets[rand_ip])
                rand_ip = rand_ip + 1
            except IndexError:
                pass

    os.system("clear")
    print("\n{}{}Initializing scanner..\nThis may take some time.\n{}".format(bold, blue, reset))
    for net in netlist:
        ip = net.lstrip().strip('\n')
        try:
            scan(ip)
        except KeyboardInterrupt:
            print("\n{}{}Exiting..{}".format(bold, red, reset))
            sys.exit(0)           
            
