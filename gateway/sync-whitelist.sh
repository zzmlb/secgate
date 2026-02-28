#!/bin/bash
# 同步 config.json 白名单到 iptables 规则
# 当通过 API 修改白名单后调用此脚本
bash /root/pj226/gateway/setup-iptables.sh
iptables-save > /etc/iptables/rules.v4
echo "iptables rules synced and saved"
