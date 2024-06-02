#!/bin/bash

# 创建并初始化记录文件
output_file="cpu_mem_usage_sgx.log"
echo "Timestamp,CPU_Load,DRAM_Usage" > $output_file

# 无限循环每秒记录一次数据
while true; do
    # 获取当前时间戳
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # 获取 CPU load 数据，精确到小数点后五位
    cpu_load=$(mpstat 1 1 | awk '/all/ {printf "%.5f\n", 100 - $12}')

    # 获取 DRAM usage 数据，精确到小数点后五位
    mem_info=$(free | grep Mem)
    total_mem=$(echo $mem_info | awk '{print $2}')
    used_mem=$(echo $mem_info | awk '{print $3}')
    dram_usage=$(awk -v used=$used_mem -v total=$total_mem 'BEGIN {printf "%.5f\n", (used/total)*100}')

    # 将数据写入文件
    echo "$timestamp,$cpu_load,$dram_usage" >> $output_file

    # 等待 1 秒钟
    sleep 1
done