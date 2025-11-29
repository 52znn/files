#!/bin/bash

CONFIG="/etc/soga/soga.conf"

# ====== 设置 type ======
read -p "请输入 type（回车默认 v2board）: " TYPE
if [ -z "$TYPE" ]; then
    TYPE="v2board"
fi

# ====== 选择 server_type ======
echo "请选择要设置的 server_type："
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
        echo "输入无效！必须是 1~4."
        exit 1
        ;;
esac

# ====== 输入 webapi_url ======
read -p "请输入 webapi_url（可留空）: " WEBAPI_URL

# ====== 输入 webapi_key ======
read -p "请输入 webapi_key（可留空）: " WEBAPI_KEY

# ====== 输入 cert_mode ======
read -p "请输入 cert_mode（回车默认 http）: " CERT_MODE
if [ -z "$CERT_MODE" ]; then
    CERT_MODE="http"
fi

# ====== 输入 cert_domain ======
read -p "请输入 cert_domain（可留空）: " CERT_DOMAIN

# ====== 输入 default_dns ======
#read -p "请输入 default_dns（可留空）: " DEFAULT_DNS

# ====== 修改 type ======
if grep -q "^type=" "$CONFIG"; then
    sed -i "s/^type=.*/type=$TYPE/" "$CONFIG"
else
    echo "type=$TYPE" >> "$CONFIG"
fi

# ====== 修改 server_type ======
if grep -q "^server_type=" "$CONFIG"; then
    sed -i "s/^server_type=.*/server_type=$SERVER_TYPE/" "$CONFIG"
else
    echo "server_type=$SERVER_TYPE" >> "$CONFIG"
fi

# ====== 修改 webapi_url ======
if grep -q "^webapi_url=" "$CONFIG"; then
    sed -i "s|^webapi_url=.*|webapi_url=$WEBAPI_URL|" "$CONFIG"
else
    echo "webapi_url=$WEBAPI_URL" >> "$CONFIG"
fi

# ====== 修改 webapi_key ======
if grep -q "^webapi_key=" "$CONFIG"; then
    sed -i "s|^webapi_key=.*|webapi_key=$WEBAPI_KEY|" "$CONFIG"
else
    echo "webapi_key=$WEBAPI_KEY" >> "$CONFIG"
fi

# ====== 修改 cert_mode ======
if grep -q "^cert_mode=" "$CONFIG"; then
    sed -i "s/^cert_mode=.*/cert_mode=$CERT_MODE/" "$CONFIG"
else
    echo "cert_mode=$CERT_MODE" >> "$CONFIG"
fi

# ====== 修改 cert_domain ======
if grep -q "^cert_domain=" "$CONFIG"; then
    sed -i "s/^cert_domain=.*/cert_domain=$CERT_DOMAIN/" "$CONFIG"
else
    echo "cert_domain=$CERT_DOMAIN" >> "$CONFIG"
fi

# ====== 修改 default_dns ======
#if grep -q "^default_dns=" "$CONFIG"; then
#    sed -i "s/^default_dns=.*/default_dns=$DEFAULT_DNS/" "$CONFIG"
#else
#    echo "default_dns=$DEFAULT_DNS" >> "$CONFIG"
#fi

echo "配置已更新："
echo "type=$TYPE"
echo "server_type=$SERVER_TYPE"
echo "webapi_url=$WEBAPI_URL"
echo "webapi_key=$WEBAPI_KEY"
echo "cert_mode=$CERT_MODE"
echo "cert_domain=$CERT_DOMAIN"
#echo "default_dns=$DEFAULT_DNS"
