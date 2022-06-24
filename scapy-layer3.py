#!/usr/bin/python

import os, sys


def perm_check():
    USERID = os.getuid()
    if USERID != 0:
        print('[!] run this script as root.')
        sys.exit(1)


perm_check()

import argparse, subprocess, multiprocessing, socket
from scapy.all import sr1, IP, ICMP
from scapy.all import *

def run_core(dst):
    try:
        answer = sr1(IP(dst=dst) / ICMP(type='echo-request'), timeout=1, verbose=False)
    except Exception as err:
        print(err)
        sys.exit(1)
    else:
        if answer == None:
            print(f'{dst} -> Down')
        else:
            print(f'{dst} -> Up')


def check_ip(ip):
    try:
        socket.inet_aton(ip)
    except Exception as err:
        # print(err)
        print(f'[!] invalid ip address [{ip}]')
        sys.exit(1)


parser = argparse.ArgumentParser(description='SCAPY LAYER3 [ICMP] Host Discovery')
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
group.add_argument('-r', '--range',
                   metavar='<IP RANGE>',
                   dest='ip_range',
                   help='specify ip range to ping. Can be specified as 192.168.48.0 or 192.168.48.0/24 or 192.168.48.0-255')
args = parser.parse_args()

if args.target_ip:
    dst = args.target_ip
    check_ip(dst)
    run_core(dst=dst)


def interface_check(interface):
    rc = subprocess.run(['ip', 'addr', 'show', interface], stdout=open('/dev/null'), stderr=open('/dev/null'))
    if rc.returncode != 0:
        print(f'[!] interface[{interface}] seems invalid. please double check.')
        sys.exit(1)


if args.interface:
    interface = str(args.interface)
    interface_check(interface)

    ip = \
    subprocess.check_output(f"ip addr show {interface} | grep inet | grep -v inet6 | sed 's/  //g' | cut -d ' ' -f 2",
                            shell=True).decode().strip().split('/')[0]
    prefix = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.'
    processes = []
    for addr in range(1, 254):
        dst = prefix + str(addr)
        check_ip(dst)
        p = multiprocessing.Process(target=run_core, args=[dst])
        processes.append(p)
        p.start()

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
            dst = line.strip()
            check_ip(dst)
            p = multiprocessing.Process(target=run_core, args=[dst])
            processes.append(p)
            p.start()

        for p in processes:
            p.join()


def config_ip_range(ip_range):
    ok = False
    try:
        ip_range.index('/')
        ok = True
    except:
        pass
    try:
        ip_range.index('-')
        ok = True
    except:
        pass
    if not ok:
        print('[!] invalid ip range specified.')
        sys.exit(1)
    else:
        # print(ip_range)
        com = f"nmap -n -sL {ip_range} | grep 'Nmap scan report' | cut -d ' ' -f 5"
        output = subprocess.check_output(com, shell=True, stderr=open('/dev/null')).decode().rstrip('\n')
        output = output.split('\n')
        # print(output)
        # sys.exit()
        return output


if args.ip_range:
    ip_range = str(args.ip_range)
    ip_range = config_ip_range(ip_range)
    processes = []
    for addr in ip_range:
        dst = addr.strip()
        check_ip(dst)
        p = multiprocessing.Process(target=run_core, args=[dst])
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
