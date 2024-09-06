#!/bin/bash

# minitor CPU and DRAM usage
output_file="cpu_mem_usage_sgx.log"
echo "Timestamp,CPU_Load,DRAM_Usage" > $output_file

while true; do
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    cpu_load=$(mpstat 1 1 | awk '/all/ {printf "%.5f\n", 100 - $12}')

    mem_info=$(free | grep Mem)
    total_mem=$(echo $mem_info | awk '{print $2}')
    used_mem=$(echo $mem_info | awk '{print $3}')
    dram_usage=$(awk -v used=$used_mem -v total=$total_mem 'BEGIN {printf "%.5f\n", (used/total)*100}')

    echo "$timestamp,$cpu_load,$dram_usage" >> $output_file

    sleep 1
done