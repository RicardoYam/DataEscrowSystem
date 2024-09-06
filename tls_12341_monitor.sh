#!/bin/bash

output_file="tls_12341_openssl1.log"
echo "Timestamp,Local_Address,Remote_Address,State" > $output_file

pcap_file="tls_12341_traffic_openssl1.pcap"

sudo tcpdump -i any port 12341 -w $pcap_file &

tcpdump_pid=$!

while true; do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    connections=$(ss -tnp | grep :12341)

    if [ -z "$connections" ]; then
        echo "$timestamp,No connections" >> $output_file
    else
        while read -r line; do
            local_address=$(echo $line | awk '{print $4}')
            remote_address=$(echo $line | awk '{print $5}')
            state=$(echo $line | awk '{print $1}')
            pid_program=$(echo $line | awk '{print $7}')
            echo "$timestamp,$local_address,$remote_address,$state,$pid_program" >> $output_file
        done <<< "$connections"
    fi

    sleep 1
done

trap "kill $tcpdump_pid" EXIT