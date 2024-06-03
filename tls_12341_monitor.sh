#!/bin/bash

# 创建并初始化记录文件
output_file="tls_12341_openssl1.log"
echo "Timestamp,Local_Address,Remote_Address,State" > $output_file

# 定义捕获数据包的文件
pcap_file="tls_12341_traffic_openssl1.pcap"

# 启动 tcpdump 以捕获端口12341上的流量
sudo tcpdump -i any port 12341 -w $pcap_file &

# 获取 tcpdump 进程ID
tcpdump_pid=$!

# 无限循环每秒记录一次数据
while true; do
    # 获取当前时间戳
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # 获取12341端口的TLS连接信息
    connections=$(ss -tnp | grep :12341)

    # 如果没有连接，则记录无连接信息
    if [ -z "$connections" ]; then
        echo "$timestamp,No connections" >> $output_file
    else
        # 记录每个连接的详细信息
        while read -r line; do
            local_address=$(echo $line | awk '{print $4}')
            remote_address=$(echo $line | awk '{print $5}')
            state=$(echo $line | awk '{print $1}')
            pid_program=$(echo $line | awk '{print $7}')
            echo "$timestamp,$local_address,$remote_address,$state,$pid_program" >> $output_file
        done <<< "$connections"
    fi

    # 等待 1 秒钟
    sleep 1
done

# 当脚本终止时，停止 tcpdump
trap "kill $tcpdump_pid" EXIT