#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # 无颜色
BOLD='\033[1m'

# 默认配置
XRAY_VERSION="1.8.11"
INSTALL_DIR="/usr/local/xray"
CONFIG_DIR="/usr/local/etc/xray"
SERVICE_FILE="/etc/systemd/system/xray.service"
LOG_DIR="/var/log/xray"
TEMP_DIR="/tmp/xray-install"

# 默认参数
DEFAULT_PORT=443
DEFAULT_SNI="www.microsoft.com"
DEFAULT_SHORT_ID="$(openssl rand -hex 8)"
DEFAULT_UUID=$(cat /proc/sys/kernel/random/uuid || echo $(uuidgen))

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_failure() {
    echo -e "${RED}[✗]${NC} $1"
}

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行！"
        log_info "请使用: sudo bash $0"
        exit 1
    fi
}

# 检查系统
check_system() {
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="centos"
        PM="yum"
    elif grep -Eqi "debian|ubuntu" /etc/issue; then
        SYSTEM="debian"
        PM="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        SYSTEM="centos"
        PM="yum"
    elif grep -Eqi "arch" /etc/issue; then
        SYSTEM="arch"
        PM="pacman"
    else
        SYSTEM="unknown"
        PM=""
    fi
    
    # 检查系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            XRAY_ARCH="64"
            ;;
        aarch64|arm64)
            XRAY_ARCH="arm64-v8a"
            ;;
        armv7l)
            XRAY_ARCH="arm32-v7a"
            ;;
        *)
            XRAY_ARCH="64"
            ;;
    esac
    
    log_info "系统: $SYSTEM, 架构: $ARCH"
}

# 安装依赖
install_dependencies() {
    log_step "安装系统依赖..."
    
    case $SYSTEM in
        debian|ubuntu)
            apt update
            apt install -y curl wget unzip jq tar gzip openssl net-tools bc
            ;;
        centos)
            yum install -y curl wget unzip jq tar gzip openssl net-tools bc
            ;;
        arch)
            pacman -Syu --noconfirm curl wget unzip jq tar gzip openssl net-tools bc
            ;;
        *)
            log_error "不支持的系统！"
            exit 1
            ;;
    esac
    
    # 检查是否安装成功
    for cmd in curl wget unzip jq openssl; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd 安装失败！"
            exit 1
        fi
    done
    
    log_success "依赖安装完成"
}

# 生成随机端口
generate_random_port() {
    # 生成 20000-50000 之间的随机端口
    echo $((RANDOM % 30000 + 20000))
}

# 生成UUID
generate_uuid() {
    if command -v uuidgen &> /dev/null; then
        uuidgen
    elif command -v cat /proc/sys/kernel/random/uuid &> /dev/null; then
        cat /proc/sys/kernel/random/uuid
    else
        # 备用方案
        openssl rand -hex 16 | sed 's/\(..\)/&-/g; s/-$//'
    fi
}

# 生成shortId
generate_short_id() {
    openssl rand -hex 8
}

# 检查端口是否被占用
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        return 1
    else
        return 0
    fi
}

# 检查域名是否支持REALITY
check_reality_domain() {
    local domain=$1
    log_info "检查域名 $domain 是否支持 REALITY..."
    
    # 检查域名是否支持TLS 1.3
    if timeout 5 openssl s_client -connect "$domain:443" -tls1_3 2>/dev/null | grep -q "TLSv1.3"; then
        # 获取公钥
        local spki=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)
        if [ -n "$spki" ]; then
            echo "$spki"
            return 0
        fi
    fi
    
    return 1
}

# 获取推荐域名列表
get_recommended_domains() {
    echo "=========================================="
    echo "推荐用于 REALITY 的 SNI 列表:"
    echo "1. www.microsoft.com (默认，推荐)"
    echo "2. www.google.com"
    echo "3. www.cloudflare.com"
    echo "4. www.apple.com"
    echo "5. www.github.com"
    echo "6. www.youtube.com"
    echo "7. www.amazon.com"
    echo "8. www.facebook.com"
    echo "9. www.twitter.com"
    echo "10. www.openai.com"
    echo "=========================================="
}

# 安装Xray
install_xray() {
    log_step "下载并安装 Xray-core..."
    
    # 创建临时目录
    mkdir -p $TEMP_DIR
    cd $TEMP_DIR
    
    # 获取最新版本
    if [ "$XRAY_VERSION" = "latest" ]; then
        LATEST_VERSION=$(curl -sL "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
        if [ -z "$LATEST_VERSION" ]; then
            log_error "无法获取最新版本，使用默认版本: 1.8.11"
            XRAY_VERSION="1.8.11"
        else
            XRAY_VERSION=$LATEST_VERSION
        fi
    fi
    
    log_info "Xray-core 版本: v$XRAY_VERSION"
    
    # 下载Xray
    DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
    
    log_info "下载 Xray-core..."
    if ! wget -q --timeout=10 --tries=3 $DOWNLOAD_URL -O xray.zip; then
        log_error "下载 Xray 失败！"
        return 1
    fi
    
    # 解压
    unzip -q xray.zip
    if [ $? -ne 0 ]; then
        log_error "解压失败！"
        return 1
    }
    
    # 创建安装目录
    mkdir -p $INSTALL_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    
    # 安装Xray
    install -m 755 xray $INSTALL_DIR/
    chmod +x $INSTALL_DIR/xray
    
    # 创建符号链接
    ln -sf $INSTALL_DIR/xray /usr/local/bin/xray
    ln -sf $INSTALL_DIR/xray /usr/bin/xray 2>/dev/null
    
    # 清理临时文件
    cd /
    rm -rf $TEMP_DIR
    
    log_success "Xray-core 安装完成"
    return 0
}

# 生成配置文件
generate_config() {
    log_step "生成配置..."
    
    # 获取用户输入
    echo ""
    echo "=========================================="
    echo "       VLESS + REALITY + XHTTP 配置"
    echo "=========================================="
    
    # 端口设置
    while true; do
        read -p "输入监听端口 [默认: $DEFAULT_PORT]: " PORT
        PORT=${PORT:-$DEFAULT_PORT}
        
        if [[ $PORT =~ ^[0-9]+$ ]] && [ $PORT -ge 1 ] && [ $PORT -le 65535 ]; then
            if check_port $PORT; then
                break
            else
                log_error "端口 $PORT 已被占用，请选择其他端口！"
            fi
        else
            log_error "端口必须是1-65535之间的数字！"
        fi
    done
    
    # UUID设置
    read -p "输入UUID [回车使用随机生成]: " UUID
    UUID=${UUID:-$(generate_uuid)}
    
    # SNI设置
    get_recommended_domains
    while true; do
        read -p "输入 SNI (目标网站域名) [默认: $DEFAULT_SNI]: " SNI
        SNI=${SNI:-$DEFAULT_SNI}
        
        # 检查SNI格式
        if [[ $SNI =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            # 尝试获取公钥
            PUB_KEY=$(check_reality_domain $SNI)
            if [ $? -eq 0 ] && [ -n "$PUB_KEY" ]; then
                log_success "域名 $SNI 支持 REALITY，公钥获取成功"
                break
            else
                log_warn "域名 $SNI 可能不支持 REALITY 或无法连接"
                read -p "是否继续使用此域名? [y/N]: " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    PUB_KEY=""
                    break
                fi
            fi
        else
            log_error "域名格式不正确！"
        fi
    done
    
    # 服务名称
    read -p "输入服务名称 [默认: www.microsoft.com]: " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-"www.microsoft.com"}
    
    # 短ID设置
    read -p "输入短ID [回车使用随机生成]: " SHORT_ID
    SHORT_ID=${SHORT_ID:-$(generate_short_id)}
    
    # 生成Xray配置文件
    cat > $CONFIG_DIR/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "$LOG_DIR/access.log",
    "error": "$LOG_DIR/error.log"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "block",
        "domain": [
          "geosite:category-ads-all"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:cn"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:cn",
          "geoip:private"
        ]
      }
    ]
  },
  "inbounds": [
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$SNI:443",
          "serverNames": [
            "$SERVER_NAME"
          ],
          "privateKey": "$(openssl rand -hex 32)",
          "shortIds": [
            "$SHORT_ID"
          ],
          "fingerprint": "chrome"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
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
  ],
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 120
      }
    }
  }
}
EOF
    
    # 生成私钥
    PRIVATE_KEY=$(openssl rand -hex 32)
    # 更新配置文件中的私钥
    sed -i "s/\"privateKey\": \".*\"/\"privateKey\": \"$PRIVATE_KEY\"/" $CONFIG_DIR/config.json
    
    # 计算公钥
    PUBLIC_KEY=$(echo -n $PRIVATE_KEY | openssl pkey -inform hex -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64)
    
    # 保存配置信息
    cat > $CONFIG_DIR/client-config.txt << EOF
# ==========================================
# VLESS + REALITY + XHTTP 客户端配置
# ==========================================
服务器地址: $(curl -s ifconfig.me || echo "你的服务器IP")
端口: $PORT
UUID: $UUID
流控: xtls-rprx-vision
传输协议: tcp
传输层安全: reality
SNI: $SNI
服务器名称: $SERVER_NAME
公钥: $PUBLIC_KEY
短ID: $SHORT_ID
指纹: chrome
协议: vless
# ==========================================

# VLESS 链接 (推荐使用 v2rayN、Nekoray 等客户端):
vless://$UUID@$(curl -s ifconfig.me || echo "你的服务器IP"):$PORT?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&spx=%2F&serviceName=$SERVER_NAME#VLESS_Reality_XHTTP

# 二维码生成链接:
https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=$(echo -n "vless://$UUID@$(curl -s ifconfig.me || echo "你的服务器IP"):$PORT?encryption=none&flow=xtls-rprx-vision&type=tcp&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&spx=%2F&serviceName=$SERVER_NAME#VLESS_Reality_XHTTP" | jq -sRr @uri)
EOF
    
    log_success "配置文件生成完成"
    
    # 显示配置
    echo ""
    cat $CONFIG_DIR/client-config.txt
    echo ""
    
    return 0
}

# 创建服务文件
create_service() {
    log_step "创建系统服务..."
    
    cat > $SERVICE_FILE << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=$INSTALL_DIR/xray run -config $CONFIG_DIR/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    # 重载systemd
    systemctl daemon-reload
    systemctl enable xray
    
    log_success "系统服务创建完成"
    return 0
}

# 配置防火墙
configure_firewall() {
    log_step "配置防火墙..."
    
    # 获取端口
    PORT=$(grep -o '"port": [0-9]*' $CONFIG_DIR/config.json | head -1 | awk '{print $2}')
    
    if [ -z "$PORT" ]; then
        PORT=443
    fi
    
    # 检查防火墙类型
    if command -v ufw &> /dev/null; then
        # Ubuntu/Debian
        ufw allow $PORT/tcp
        ufw reload
        log_success "UFW 防火墙已配置，端口: $PORT"
        
    elif command -v firewall-cmd &> /dev/null; then
        # CentOS/RHEL/Fedora
        firewall-cmd --permanent --add-port=$PORT/tcp
        firewall-cmd --reload
        log_success "FirewallD 已配置，端口: $PORT"
        
    elif command -v iptables &> /dev/null; then
        # 使用iptables
        iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
        # 保存规则
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables.rules
        fi
        log_success "iptables 已配置，端口: $PORT"
    else
        log_warn "未检测到防火墙工具，请手动开放端口: $PORT"
    fi
    
    return 0
}

# 启动服务
start_service() {
    log_step "启动 Xray 服务..."
    
    systemctl daemon-reload
    systemctl restart xray
    sleep 2
    
    if systemctl is-active --quiet xray; then
        # 检查服务状态
        if $INSTALL_DIR/xray version &> /dev/null; then
            log_success "Xray 服务启动成功！"
            
            # 显示状态
            echo ""
            echo "=========================================="
            echo "          服务状态信息"
            echo "=========================================="
            echo "服务状态: $(systemctl is-active xray)"
            echo "运行时长: $(systemctl status xray | grep -o 'active (running) [^;]*' | cut -d' ' -f4- || echo '未知')"
            echo "监听端口: $PORT"
            echo "配置文件: $CONFIG_DIR/config.json"
            echo "日志文件: $LOG_DIR/"
            echo "=========================================="
            
            return 0
        else
            log_warn "Xray 服务已启动，但版本检查失败"
            return 1
        fi
    else
        log_error "Xray 服务启动失败！"
        journalctl -u xray -n 20 --no-pager
        return 1
    fi
}

# 安装BBR
install_bbr() {
    log_step "安装 BBR 加速..."
    
    if [[ $SYSTEM == "debian" ]] || [[ $SYSTEM == "ubuntu" ]]; then
        # Debian/Ubuntu
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        
        # 检查是否启用
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            log_success "BBR 加速已启用"
        else
            log_warn "BBR 加速启用失败，可能需要重启"
        fi
    elif [[ $SYSTEM == "centos" ]]; then
        # CentOS
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
        log_info "BBR 配置已添加，建议重启系统生效"
    else
        log_warn "不支持的系统，跳过 BBR 安装"
    fi
    
    return 0
}

# 显示菜单
show_menu() {
    clear
    echo ""
    echo -e "${PURPLE}╔════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║    VLESS + REALITY + XHTTP 一键安装脚本   ║${NC}"
    echo -e "${PURPLE}║        支持 REALITY 最新协议            ║${NC}"
    echo -e "${PURPLE}║        作者: AI助手                    ║${NC}"
    echo -e "${PURPLE}╚════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}支持系统: CentOS 7+/Ubuntu 18+/Debian 10+/Arch${NC}"
    echo -e "${CYAN}支持架构: x86_64 / ARM64 / ARMv7${NC}"
    echo ""
    echo -e "${YELLOW}请选择操作:${NC}"
    echo "1. 一键安装 VLESS + REALITY + XHTTP"
    echo "2. 仅安装 Xray-core"
    echo "3. 生成配置文件"
    echo "4. 启动/重启服务"
    echo "5. 停止服务"
    echo "6. 查看服务状态"
    echo "7. 查看配置信息"
    echo "8. 卸载 Xray"
    echo "9. 安装 BBR 加速"
    echo "0. 退出"
    echo ""
}

# 一键安装
onekey_install() {
    clear
    echo ""
    echo -e "${GREEN}开始一键安装 VLESS + REALITY + XHTTP${NC}"
    echo "=========================================="
    
    # 检查并安装依赖
    install_dependencies
    
    # 安装Xray
    if ! install_xray; then
        log_error "Xray 安装失败！"
        return 1
    fi
    
    # 生成配置
    if ! generate_config; then
        log_error "配置生成失败！"
        return 1
    fi
    
    # 创建服务
    if ! create_service; then
        log_error "服务创建失败！"
        return 1
    fi
    
    # 配置防火墙
    configure_firewall
    
    # 启动服务
    if ! start_service; then
        log_error "服务启动失败！"
        return 1
    fi
    
    # 安装BBR
    read -p "是否安装 BBR 加速? [Y/n]: " install_bbr_choice
    if [[ ! $install_bbr_choice =~ ^[Nn]$ ]]; then
        install_bbr
    fi
    
    echo ""
    echo -e "${GREEN}==========================================${NC}"
    echo -e "${GREEN}     安装完成！请保存上面的配置信息！     ${NC}"
    echo -e "${GREEN}==========================================${NC}"
    echo ""
    echo "配置文件位置: $CONFIG_DIR/config.json"
    echo "客户端配置: $CONFIG_DIR/client-config.txt"
    echo "管理命令: systemctl {start|stop|restart|status} xray"
    echo ""
    
    # 显示二维码链接
    if command -v curl &> /dev/null; then
        QR_URL=$(grep "二维码生成链接:" $CONFIG_DIR/client-config.txt | cut -d' ' -f2-)
        echo -e "${YELLOW}提示: 使用浏览器访问二维码链接，用手机扫描配置${NC}"
        echo "二维码链接: $QR_URL"
    fi
    
    return 0
}

# 卸载Xray
uninstall_xray() {
    echo ""
    echo -e "${RED}警告: 这将完全卸载 Xray 和相关配置${NC}"
    read -p "确定要卸载 Xray 吗? [y/N]: " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "卸载已取消"
        return
    fi
    
    log_step "开始卸载 Xray..."
    
    # 停止服务
    systemctl stop xray 2>/dev/null
    systemctl disable xray 2>/dev/null
    
    # 删除服务文件
    rm -f $SERVICE_FILE
    systemctl daemon-reload
    
    # 删除安装文件
    rm -rf $INSTALL_DIR
    rm -rf $CONFIG_DIR
    rm -rf $LOG_DIR
    rm -f /usr/local/bin/xray
    rm -f /usr/bin/xray 2>/dev/null
    
    log_success "Xray 卸载完成！"
}

# 查看配置信息
show_config() {
    if [ ! -f "$CONFIG_DIR/client-config.txt" ]; then
        log_error "找不到配置文件！"
        return 1
    fi
    
    echo ""
    echo -e "${GREEN}==========================================${NC}"
    echo -e "${GREEN}          当前配置信息                  ${NC}"
    echo -e "${GREEN}==========================================${NC}"
    echo ""
    cat $CONFIG_DIR/client-config.txt
    echo ""
    
    # 显示服务状态
    if systemctl is-active --quiet xray; then
        echo -e "${GREEN}服务状态: 运行中${NC}"
    else
        echo -e "${RED}服务状态: 未运行${NC}"
    fi
}

# 主函数
main() {
    # 检查权限
    check_root
    
    # 检查系统
    check_system
    
    while true; do
        show_menu
        read -p "请输入选择 [0-9]: " choice
        
        case $choice in
            1)
                onekey_install
                ;;
            2)
                install_dependencies
                install_xray
                ;;
            3)
                if [ ! -f "$INSTALL_DIR/xray" ]; then
                    log_error "请先安装 Xray-core！"
                else
                    generate_config
                fi
                ;;
            4)
                if [ ! -f "$SERVICE_FILE" ]; then
                    log_error "服务文件不存在，请先安装！"
                else
                    systemctl restart xray
                    sleep 2
                    systemctl status xray --no-pager
                fi
                ;;
            5)
                if [ -f "$SERVICE_FILE" ]; then
                    systemctl stop xray
                    log_success "服务已停止"
                else
                    log_error "服务文件不存在！"
                fi
                ;;
            6)
                if [ -f "$SERVICE_FILE" ]; then
                    systemctl status xray --no-pager
                else
                    log_error "服务文件不存在！"
                fi
                ;;
            7)
                show_config
                ;;
            8)
                uninstall_xray
                ;;
            9)
                install_bbr
                ;;
            0)
                echo ""
                log_info "感谢使用！"
                exit 0
                ;;
            *)
                log_error "无效的选择！"
                ;;
        esac
        
        echo ""
        read -p "按回车键返回菜单..."
    done
}

# 显示欢迎信息
clear
echo ""
echo -e "${PURPLE}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║      VLESS + REALITY + XHTTP 一键安装脚本        ║${NC}"
echo -e "${PURPLE}║                                                    ║${NC}"
echo -e "${PURPLE}║  🔒 基于 REALITY 协议，无证书、更快、更安全        ║${NC}"
echo -e "${PURPLE}║  🚀 支持 XTLS Vision 流控，性能提升显著           ║${NC}"
echo -e "${PURPLE}║  🌍 自动配置伪装，对抗主动探测                    ║${NC}"
echo -e "${PURPLE}║  🛡️  支持 BBR 加速，提升网络性能                 ║${NC}"
echo -e "${PURPLE}║  📱 生成客户端配置和二维码，方便使用              ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}注意: 此脚本需要服务器可正常访问以下网站:${NC}"
echo "- GitHub (下载 Xray-core)"
echo "- 您选择的 SNI 域名 (如 www.microsoft.com)"
echo ""
read -p "按回车键开始安装，或 Ctrl+C 退出..."

# 运行主函数
main "$@"