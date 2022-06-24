#!/bin/bash 

quit() {
	exit 1
}

trap quit SIGINT
trap quit SIGTERM

perm_check() {
	USERID=$(id -u $USER)
	if [[ $USERID -ne 0 ]]
	then
		echo '[!] run this script as root.'
		quit
	fi
}

perm_check


help() {
	echo "[*] Layer 2 Host Discovery with arping using ARP packets"
        echo "[*] Usage: $0 -h <IP> [ -i <INTERFACE>] [-l <IP LIST>]"
	echo "[*] Options: "
	echo "[*] -i| --interface <INTERFACE> Network Interface to use"
	echo "[*] -h| --host <IP ADDRESS> check this single ip only."
	echo "[*] -l| --ip-list <FILE> load ip's from this file"
        echo "[*] Ex: $0 -i eth0"
        exit 0
}
[[ "$#" -lt 2 ]] && help


while [[ "$#" -gt 0 ]]; do
    case "$1" in
	-h|--host) host_ip="$2"; shift;;
        -i|--interface) interface="$2"; shift ;;
	-l|--ip-list) ip_list="$2"; shift;;
        *) echo "Unknown parameter passed: $1"; help; exit 1 ;;
    esac
    shift
done

run_core() {
	ip="$1"
	arping -c 1 "$ip" | grep 'bytes from' | cut -d ' ' -f 4,5 | sed -e 's/(//' -e 's/)//' -e 's/:$//' -e 's/ / -> /' | awk '{ print $3,$2,$1 }' 
}


[[ ! -z "$host_ip" ]] && run_core "$host_ip"

check_interface() {
	interface="$1"
	ip address show "$interface" > /dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo "[!] interface [\"$interface\"] seems invalid. please double check."
        	quit
	fi
}

if [[ ! -z "$interface" ]] 
then
	check_interface "$interface"
	interface_ip=$(ip address show "$interface" | grep inet | grep -v 'inet6' | cut -d '/' -f 1  | sed 's/ \+/ /' | cut -d ' ' -f 3)
	prefix=$(echo "$interface_ip" | cut -d '.' -f 1-3)
	pids=""
	for addr in {1..254}
	do
		run_core "$prefix.$addr" &
		pids+=" $!"
	
	done	
	wait $pids
fi


check_file() {
	file="$1"
	[[ ! -f "$file" ]] && echo "[!] file [$file] not exists." && quit 
	[[ ! -r "$file" ]] && echo "[!] file [$file] not readable." && quit 
}

if [[ ! -z "$ip_list" ]]
then
	check_file "$ip_list"
	pids=""
	for addr in $(cat "$ip_list")
	do
		run_core "$addr" &
		pids+=" $!"
	done
	wait $pids
fi
