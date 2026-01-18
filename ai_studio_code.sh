#!/bin/bash

# 1. 检查 Root 权限
if [ "$(id -u)" != "0" ]; then
    echo "请以 root 用户运行此脚本！"
    exit 1
fi

echo "正在更新系统并安装依赖..."
apt update && apt install -y curl jq openssl

# 2. 安装/更新 Xray-core (官方脚本)
echo "正在安装最新版 Xray..."
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 3. 生成配置参数
UUID=$(xray uuid)
# 生成 Reality 密钥对
KEYS=$(xray x25519)
PRIVATE_KEY=$(echo "$KEYS" | grep "Private" | awk '{print $3}')
PUBLIC_KEY=$(echo "$KEYS" | grep "Public" | awk '{print $3}')
SHORT_ID=$(openssl rand -hex 4)
# 目标网站 (可以是 microsoft.com, apple.com, amazon.com 等)
DEST="www.microsoft.com:443"
SERVER_NAME="www.microsoft.com"

# 4. 写入配置文件 config.json
cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "" 
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST",
          "xver": 0,
          "serverNames": [
            "$SERVER_NAME"
          ],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": [
            "$SHORT_ID"
          ]
        },
        "xhttpSettings": {
          "path": "/xhttp-path",
          "mode": "auto"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

# 5. 重启 Xray 服务
systemctl restart xray
systemctl enable xray

# 6. 输出客户端配置信息
CLEAR='\033[0m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'

echo -e "${GREEN}=== 安装完成！请保存以下信息 ===${CLEAR}"
echo -e "地址 (Address): ${YELLOW}$(curl -s ifconfig.me)${CLEAR}"
echo -e "端口 (Port): ${YELLOW}443${CLEAR}"
echo -e "用户ID (UUID): ${YELLOW}${UUID}${CLEAR}"
echo -e "流控 (Flow): ${YELLOW}空 (XHTTP不需要xtls-rprx-vision)${CLEAR}"
echo -e "传输协议 (Network): ${YELLOW}xhttp${CLEAR}"
echo -e "伪装类型 (Header type): ${YELLOW}none${CLEAR}"
echo -e "XHTTP路径 (Path): ${YELLOW}/xhttp-path${CLEAR}"
echo -e "传输层安全 (TLS): ${YELLOW}reality${CLEAR}"
echo -e "SNI (ServerName): ${YELLOW}${SERVER_NAME}${CLEAR}"
echo -e "指纹 (Fingerprint): ${YELLOW}chrome${CLEAR}"
echo -e "PublicKey: ${YELLOW}${PUBLIC_KEY}${CLEAR}"
echo -e "ShortId: ${YELLOW}${SHORT_ID}${CLEAR}"
echo -e "${GREEN}===================================${CLEAR}"
echo "注意：客户端(v2rayN/Nekoray)必须支持 Xray 1.8.24+ 或 v24.12+ 核心才能连接 XHTTP。"