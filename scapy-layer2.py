#!/usr/bin/python

import os,sys
def perm_check():
    USERID = os.getuid()
    if USERID != 0:
        print('[!] run this script as root.')
        sys.exit(1)

perm_check()

import logging
import argparse, subprocess,multiprocessing
from scapy.all import *


def run_core(pdst):
    try:
        answer=sr1(ARP(pdst=pdst),timeout=2, verbose=False)
    except Exception as err:
        print(err)
        sys.exit(1)
    else:
        if answer == None:
            pass
        else:
            print(f'{pdst} -> {answer.hwsrc}')

parser = argparse.ArgumentParser(description='SCAPY ARP Host Discovery')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-i', '--interface',
        metavar='<INTERFACE>',
        dest='interface',
        help='Interface to discover hosts.')
group.add_argument('-p', '--ip',
        metavar='<TARGET IP>',
        dest='target_ip',
        help='Target this single host only.')
group.add_argument('-l', '--ip-list',
        metavar='<IP LIST>',
        dest='ip_list',
        help='file containing ips separated by newline')
args = parser.parse_args()

if args.target_ip:
    run_core(pdst=args.target_ip)


def interface_check(interface):
    rc = subprocess.run(['ip', 'addr', 'show', interface], stdout=open('/dev/null'), stderr=open('/dev/null'))
    if rc.returncode != 0:
        print(f'[!] interface[{interface}] seems invalid. please double check.')
        sys.exit(1)

if args.interface:
    interface = str(args.interface)
    interface_check(interface)
    
    ip = subprocess.check_output(f"ip addr show {interface} | grep inet | grep -v inet6 | sed 's/  //g' | cut -d ' ' -f 2", shell=True).decode().strip().split('/')[0]
    prefix = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.'
    processes = []
    for addr in range(1,254):
        pdst = prefix + str(addr)
        p = multiprocessing.Process(target=run_core, args=[pdst]) 
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


def file_check(file):
    try:
        open(file)
    except Exception as err:
        print(err)
        sys.exit(1)

if args.ip_list:
    ip_list = str(args.ip_list)
    file_check(ip_list)
    processes = []
    with open(ip_list) as ips:
        for line in ips:
            pdst = line.strip()
            p = multiprocessing.Process(target=run_core, args=[pdst]) 
            processes.append(p)
            p.start()

        for p in processes:
            p.join()

        
