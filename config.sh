#!/bin/bash

CONFIG="/etc/soga/soga.conf"

# ====== 选择 server_type ======
echo "请选择要设置的代理类型："
echo "1) shadowsocks"
echo "2) v2ray"
echo "3) trojan"
echo "4) hysteria"
echo

read -p "请输入数字 (1-4): " choice

case $choice in
    1) TYPE="shadowsocks" ;;
    2) TYPE="v2ray" ;;
    3) TYPE="trojan" ;;
    4) TYPE="hysteria" ;;
    *) 
        echo "❌ 输入无效！必须是 1~4."
        exit 1
        ;;
esac

# ====== 输入 node_id ======
echo
read -p "请输入 node_id（数字，例如：1）: " NODE_ID
if [ -z "$NODE_ID" ]; then
    echo "❌ node_id 不能为空！"
    exit 1
fi

# ====== 输入 webapi_url ======
echo
read -p "请输入 webapi_url（例如：https://example.com）: " WEBAPI_URL
if [ -z "$WEBAPI_URL" ]; then
    echo "❌ webapi_url 不能为空！"
    exit 1
fi

# ====== 输入 webapi_key ======
echo
read -p "请输入 webapi_key: " WEBAPI_KEY
if [ -z "$WEBAPI_KEY" ]; then
    echo "❌ webapi_key 不能为空！"
    exit 1
fi

# ====== 输入 cert_domain ======
echo
read -p "请输入 cert_domain（例如 node.example.com）: " CERT_DOMAIN
if [ -z "$CERT_DOMAIN" ]; then
    echo "❌ cert_domain 不能为空！"
    exit 1
fi

# ====== 输入 default_dns ======
echo
read -p "请输入流媒体解锁DNS，回车跳过: " DEFAULT_DNS

# ====== 写入 server_type ======
if grep -q "^server_type=" "$CONFIG"; then
    sed -i "s/^server_type=.*/server_type=${TYPE}/" "$CONFIG"
else
    echo "server_type=${TYPE}" >> "$CONFIG"
fi

# ====== 写入 node_id ======
if grep -q "^node_id=" "$CONFIG"; then
    sed -i "s/^node_id=.*/node_id=${NODE_ID}/" "$CONFIG"
else
    echo "node_id=${NODE_ID}" >> "$CONFIG"
fi

# ====== 写入 webapi_url ======
if grep -q "^webapi_url=" "$CONFIG"; then
    sed -i "s|^webapi_url=.*|webapi_url=${WEBAPI_URL}|" "$CONFIG"
else
    echo "webapi_url=${WEBAPI_URL}" >> "$CONFIG"
fi

# ====== 写入 webapi_key ======
if grep -q "^webapi_key=" "$CONFIG"; then
    sed -i "s|^webapi_key=.*|webapi_key=${WEBAPI_KEY}|" "$CONFIG"
else
    echo "webapi_key=${WEBAPI_KEY}" >> "$CONFIG"
fi

# ====== 写入 cert_domain ======
if grep -q "^cert_domain=" "$CONFIG"; then
    sed -i "s|^cert_domain=.*|cert_domain=${CERT_DOMAIN}|" "$CONFIG"
else
    echo "cert_domain=${CERT_DOMAIN}" >> "$CONFIG"
fi

# ====== 写入 default_dns ======
if [ -n "$DEFAULT_DNS" ]; then
    if grep -q "^default_dns=" "$CONFIG"; then
        sed -i "s|^default_dns=.*|default_dns=${DEFAULT_DNS}|" "$CONFIG"
    else
        echo "default_dns=${DEFAULT_DNS}" >> "$CONFIG"
    fi
    echo "✔ default_dns 已更新为：${DEFAULT_DNS}"
else
    echo "✔ default_dns 跳过，不修改"
fi

echo
echo "✔ 配置已更新成功："
echo "  server_type=${TYPE}"
echo "  node_id=${NODE_ID}"
echo "  webapi_url=${WEBAPI_URL}"
echo "  webapi_key=${WEBAPI_KEY}"
echo "  cert_domain=${CERT_DOMAIN}"
[ -n "$DEFAULT_DNS" ] && echo "  default_dns=${DEFAULT_DNS}" || echo "  default_dns（未修改）"
echo
echo "完成！"
