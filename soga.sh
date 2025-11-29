#!/bin/bash

CONFIG="/etc/soga/soga.conf"

echo "====== Soga 配置脚本 ======"

# ====== 设置 type（默认 v2board） ======
read -p "请输入 type（回车默认 v2board）: " TYPE
[ -z "$TYPE" ] && TYPE="v2board"

# ====== 选择 server_type（必须选择 1-4） ======
echo "请选择要设置的 server_type："
echo "1) shadowsocks"
echo "2) v2ray"
echo "3) trojan"
echo "4) hysteria"
read -p "请输入数字 (1-4): " choice

case "$choice" in
    1) SERVER_TYPE="shadowsocks" ;;
    2) SERVER_TYPE="v2ray" ;;
    3) SERVER_TYPE="trojan" ;;
    4) SERVER_TYPE="hysteria" ;;
    *) 
       echo "输入无效，使用默认 v2ray"
       SERVER_TYPE="v2ray"
       ;;
esac

# ====== 输入可留空的选项 ======
read -p "请输入 webapi_url（可留空）: " WEBAPI_URL
read -p "请输入 webapi_key（可留空）: " WEBAPI_KEY
read -p "请输入 cert_mode（回车默认 http）: " CERT_MODE
[ -z "$CERT_MODE" ] && CERT_MODE="http"
read -p "请输入 cert_domain（可留空）: " CERT_DOMAIN
read -p "请输入 default_dns（可留空）: " DEFAULT_DNS

# ====== 写入配置函数 ======
update_config() {
    local key=$1
    local value=$2
    if grep -q "^$key=" "$CONFIG"; then
        sed -i "s|^$key=.*|$key=$value|" "$CONFIG"
    else
        echo "$key=$value" >> "$CONFIG"
    fi
}

update_config "type" "$TYPE"
update_config "server_type" "$SERVER_TYPE"
update_config "webapi_url" "$WEBAPI_URL"
update_config "webapi_key" "$WEBAPI_KEY"
update_config "cert_mode" "$CERT_MODE"
update_config "cert_domain" "$CERT_DOMAIN"
update_config "default_dns" "$DEFAULT_DNS"

echo "====== 配置已更新 ======"
echo "type=$TYPE"
echo "server_type=$SERVER_TYPE"
echo "webapi_url=$WEBAPI_URL"
echo "webapi_key=$WEBAPI_KEY"
echo "cert_mode=$CERT_MODE"
echo "cert_domain=$CERT_DOMAIN"
echo "default_dns=$DEFAULT_DNS"
