#!/bin/bash
set -e

WORKDIR="/opt/realm"
mkdir -p $WORKDIR
cd $WORKDIR

echo -e "\033[36m====== Nuro REALM 高性能加密隧道一键管理脚本（支持 TLS 批量+CA 拉取）======\033[0m"
echo "项目地址: https://github.com/zhboner/realm"
echo "免责声明：仅供学习与交流，请勿用于非法用途。"
echo -e "脚本将在 \033[32m/opt/realm/\033[0m 目录下自动部署和运行。\n"
sleep 1

REALM_BIN="/usr/local/bin/realm"
CONF_FILE="$WORKDIR/realm.json"
RULES_FILE="$WORKDIR/rules.txt"
ROLE_FILE="$WORKDIR/.realm_role"
INIT_FLAG="$WORKDIR/.realm_inited"
CERT_FILE="$WORKDIR/cert.pem"
KEY_FILE="$WORKDIR/key.pem"
CA_FILE="$WORKDIR/ca.pem"
CA_TOKEN_FILE="$WORKDIR/ca_token.txt"

gen_pw() { tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16; }
gen_token() { tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32; }

install_realm() {
    echo "[*] 自动下载并安装最新 realm 二进制..."

    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)
            PKG="realm-x86_64-unknown-linux-gnu.tar.gz"
            ;;
        aarch64|arm64)
            PKG="realm-aarch64-unknown-linux-gnu.tar.gz"
            ;;
        *)
            echo "暂不支持该架构: $arch"
            return 1
            ;;
    esac

    VERSION=$(curl -s https://api.github.com/repos/zhboner/realm/releases/latest | grep tag_name | cut -d '"' -f4)
    if [ -z "$VERSION" ]; then
        echo "无法获取 realm 最新版本号，网络或 Github API 问题。"
        return 1
    fi

    URL="https://github.com/zhboner/realm/releases/download/$VERSION/$PKG"
    echo "[*] 下载地址: $URL"

    cd /tmp
    rm -rf realm-* realm.tar.gz
    wget -O realm.tar.gz "$URL" || { echo "下载失败！"; return 1; }
    tar -xzvf realm.tar.gz || { echo "解压失败！"; return 1; }
    BIN=$(tar -tzf realm.tar.gz | grep '^realm$' || echo realm)
    mv -f $BIN /usr/local/bin/realm
    chmod +x /usr/local/bin/realm

    echo "[√] realm ($VERSION) 已安装/升级到 /usr/local/bin/realm"
    read -p "按回车返回菜单..."
}

generate_cert() {
    openssl req -x509 -newkey rsa:2048 -keyout $KEY_FILE -out $CERT_FILE -days 3650 -nodes -subj "/CN=realm"
    cp $CERT_FILE $CA_FILE
    echo "[√] 证书($CERT_FILE)和私钥($KEY_FILE)已生成"
}

is_inited() { [ -f "$INIT_FLAG" ]; }
detect_role() { [ -f "$ROLE_FILE" ] && cat "$ROLE_FILE" || echo "unknown"; }

init_server() {
    clear
    echo "=== Realm 服务端初始化 ==="
    echo "[1] 支持 TLS/非TLS，每条规则独立，证书自动生成"
    touch $RULES_FILE
    echo "server" > $ROLE_FILE
    touch $INIT_FLAG
    echo -e "\033[32m服务端基础配置完成，正在自动重启服务...\033[0m"
    read -p "按回车继续启动 realm..."
    restart_server
}

init_client() {
    clear
    echo "=== Realm 客户端初始化 ==="
    touch $RULES_FILE
    echo "client" > $ROLE_FILE
    touch $INIT_FLAG
    echo -e "\033[36m客户端基础配置完成，正在自动重启服务...\033[0m"
    read -p "按回车继续启动 realm..."
    restart_client
}

# busybox httpd + bash 实现 CA 拉取服务（Token 校验，无依赖）
start_ca_server() {
    # 检查 CA 证书文件
    if [ ! -f "$CA_FILE" ] || [ ! -s "$CA_FILE" ]; then
        echo "未检测到 CA 证书($CA_FILE)，请先启用 TLS 并生成证书！"
        sleep 1
        return
    fi
    # 自动安装 busybox
    if ! command -v busybox >/dev/null 2>&1; then
        apt update -y >/dev/null 2>&1
        apt install -y busybox >/dev/null 2>&1
    fi
    [ -f "$CA_TOKEN_FILE" ] || gen_token > "$CA_TOKEN_FILE"
    CA_TOKEN=$(cat "$CA_TOKEN_FILE")
    mkdir -p $WORKDIR/cgi-bin
    cat > $WORKDIR/cgi-bin/ca.cgi <<EOF
#!/bin/sh
echo "Content-type: application/x-pem-file"
echo
if [ "\$(echo \$QUERY_STRING | grep token=$CA_TOKEN)" ]; then
  cat $CA_FILE
else
  echo "Invalid or missing token"
fi
EOF
    chmod +x $WORKDIR/cgi-bin/ca.cgi
    pkill -f "busybox httpd.*-p 9001" 2>/dev/null || true
    cd $WORKDIR
    nohup busybox httpd -f -p 9001 -h . -c cgi-bin > ca_httpd.log 2>&1 &
    PUB_IP=$(curl -s --max-time 4 https://api.ipify.org | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [ -z "$PUB_IP" ]; then
        PUB_IP=$(hostname -I | awk '{print $1}')
    fi
    echo "[√] CA 拉取服务已启动 (9001)，Token: $CA_TOKEN"
    echo "curl \"http://$PUB_IP:9001/cgi-bin/ca.cgi?token=$CA_TOKEN\" -o ca.pem"
    read -p "按回车返回菜单..."
}

stop_ca_server() {
    pkill -f "busybox httpd.*-p 9001" 2>/dev/null
    RETVAL=$?
    rm -f $WORKDIR/cgi-bin/ca.cgi
    if [ $RETVAL -eq 0 ]; then
        echo "CA 服务已停止！"
    else
        echo "未检测到 CA 服务，无需停止。"
    fi
    read -p "按回车返回菜单..."
}

show_ca_token() {
    if [ ! -f "$CA_FILE" ] || [ ! -s "$CA_FILE" ]; then
        echo "未检测到 CA 证书($CA_FILE)，请先启用 TLS 并生成证书！"
        sleep 1
        return
    fi
    [ -f "$CA_TOKEN_FILE" ] || { echo "未生成 CA Token，先启动一次 CA 拉取服务！"; sleep 1; return; }
    CA_TOKEN=$(cat "$CA_TOKEN_FILE")
    PUB_IP=$(curl -s --max-time 4 https://api.ipify.org | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
    if [ -z "$PUB_IP" ]; then
        PUB_IP=$(hostname -I | awk '{print $1}')
    fi
    echo "[*] CA 拉取 Token: $CA_TOKEN"
    echo "[*] CA 拉取命令："
    echo "curl \"http://$PUB_IP:9001/ca.cgi?token=$CA_TOKEN\" -o ca.pem"
    read -p "按回车返回菜单..."
}

add_rule() {
    is_inited || { echo -e "\e[31m请先初始化配置！\e[0m"; sleep 2; return; }
    role=$(detect_role)
    echo "=== 添加端口转发规则 ==="
    if [[ $role == "server" ]]; then
        read -p "监听端口: " LPORT
        read -p "目标 IP:端口（如 127.0.0.1:8080）: " TARGET
        read -p "是否为此规则启用 TLS? (y/N): " use_tls
        if [[ "$use_tls" =~ ^[Yy]$ ]]; then
            [ -f "$CERT_FILE" ] || generate_cert
            TLS="true"
        else
            TLS="false"
        fi
        PW=$(gen_pw)
        echo "$LPORT $TARGET $PW $TLS" >> $RULES_FILE
        echo "已添加: $LPORT --> $TARGET, 密码: $PW, TLS: $TLS"
    else
        read -p "本地监听端口: " LPORT
        read -p "服务端 IP:端口: " RADDR
        read -p "目标 IP:端口: " TARGET
        read -p "服务器密码: " PW
        read -p "是否启用 TLS? (y/N): " use_tls
        if [[ "$use_tls" =~ ^[Yy]$ ]]; then
            # 自动从RADDR提取IP
            S_IP=$(echo "$RADDR" | cut -d: -f1)
            CA_FILENAME="ca-${S_IP}.pem"
            echo "请粘贴服务端生成的 curl 命令（整条粘贴即可回车）："
            read -r CA_CURL_CMD
            CA_URL=$(echo "$CA_CURL_CMD" | grep -oP 'http://[0-9\.]+:9001/cgi-bin/ca\.cgi\?token=[^"]+')
            if [[ -z "$CA_URL" ]]; then
                echo "命令无效，请检查格式！"
                return 1
            fi
            curl "$CA_URL" -o "$WORKDIR/$CA_FILENAME" || { echo "CA 拉取失败，请检查命令！"; return 1; }
            TLS="true"
        else
            TLS="false"
            CA_FILENAME=""
        fi
        echo "$LPORT $RADDR $TARGET $PW $TLS $CA_FILENAME" >> $RULES_FILE
        echo "已添加: $LPORT -> $RADDR -> $TARGET (密码: $PW, TLS: $TLS, CA: $CA_FILENAME)"
    fi
    sleep 1
    gen_conf
    # 自动重启
    if [[ $role == "server" ]]; then
        restart_server
    else
        restart_client
    fi
    read -p "按回车返回菜单..."
}

del_rule() {
    is_inited || { echo -e "\e[31m请先初始化配置！\e[0m"; sleep 2; return; }
    [ ! -s "$RULES_FILE" ] && { echo "没有可删除的规则！"; sleep 1; read -p "按回车返回菜单..."; return; }
    echo "当前端口转发规则："
    nl -w2 $RULES_FILE
    while true; do
        read -p "输入要删除的序号: " IDX
        if [[ "$IDX" =~ ^[0-9]+$ ]] && [ "$IDX" -ge 1 ] && [ "$IDX" -le "$(wc -l < $RULES_FILE)" ]; then
            sed -i "${IDX}d" $RULES_FILE
            echo "已删除 #$IDX"
            sleep 1
            gen_conf
            role=$(detect_role)
            if [[ $role == "server" ]]; then
                restart_server
            else
                restart_client
            fi
            break
        else
            echo "无效选择，请输入正确的序号。"
        fi
    done
    read -p "按回车返回菜单..."
}

view_rules() {
    is_inited || { echo -e "\e[31m请先初始化配置！\e[0m"; sleep 2; return; }
    echo -e "\n[当前端口规则]"
    if [ -s "$RULES_FILE" ]; then
        nl -w2 $RULES_FILE
    else
        echo "无转发规则"
    fi
    echo
    read -p "按回车返回菜单..." _
}

show_server_info() {
    echo -e "\n\033[33m[服务端核心信息]\033[0m"
    if [ -s "$RULES_FILE" ]; then
        awk '{print "监听端口: " $1 ", 目标: " $2 ", 密码: " $3 ", TLS: " $4}' $RULES_FILE
        if [ -f "$CERT_FILE" ]; then
            echo "TLS 证书: $CERT_FILE"
        fi
    else
        echo "无规则"
    fi
    echo
    read -p "按回车返回菜单..."
}

server_status() {
    echo -e "\n\033[32m[服务端进程状态]\033[0m"
    if [ ! -s "$RULES_FILE" ]; then
        echo -e "\033[33m尚未添加任何端口转发规则，请先添加规则！\033[0m"
    else
        PID=$(pgrep -f "realm.*-c $CONF_FILE")
        if [ -n "$PID" ]; then
            echo "realm 已运行，进程ID：$PID"
            ss -ntulp | grep realm | grep LISTEN
        else
            echo "realm 未运行"
        fi
    fi
    echo
    read -p "按回车返回菜单..."
}

client_status() {
    echo -e "\n\033[32m[客户端进程状态]\033[0m"
    if [ ! -s "$RULES_FILE" ]; then
        echo -e "\033[33m尚未添加任何端口转发规则，请先添加规则！\033[0m"
    else
        PID=$(pgrep -f "realm.*-c $CONF_FILE")
        if [ -n "$PID" ]; then
            echo "realm 已运行，进程ID：$PID"
            ss -ntulp | grep realm | grep LISTEN
        else
            echo "realm 未运行"
        fi
    fi
    echo
    read -p "按回车返回菜单..."
}

gen_conf() {
    ROLE=$(detect_role)
    echo '{ "log": { "level": "info", "output": "stdout" }, "endpoints": [' > $CONF_FILE
    COUNT=$(wc -l < $RULES_FILE)
    IDX=1

    if [ "$ROLE" = "server" ]; then
        while read LPORT TARGET PW TLS _; do
            SEP=","
            [ "$IDX" = "$COUNT" ] && SEP=""
            if [ "$TLS" = "true" ]; then
                cat >> $CONF_FILE <<EOF
  {
    "listen": "0.0.0.0:$LPORT",
    "remote": "$TARGET",
    "tls": {
      "enabled": true,
      "certificate": "$CERT_FILE",
      "key": "$KEY_FILE"
    },
    "transport": "quic",
    "udp": true,
    "protocol": "shadowsocks",
    "method": "aes-256-gcm",
    "password": "$PW"
  }$SEP
EOF
            else
                cat >> $CONF_FILE <<EOF
  {
    "listen": "0.0.0.0:$LPORT",
    "remote": "$TARGET",
    "tls": {
      "enabled": false
    },
    "transport": "quic",
    "udp": true,
    "protocol": "shadowsocks",
    "method": "aes-256-gcm",
    "password": "$PW"
  }$SEP
EOF
            fi
            IDX=$((IDX+1))
        done < $RULES_FILE
    else
        while read LPORT RADDR TARGET PW TLS CA_FILENAME; do
            SEP=","
            [ "$IDX" = "$COUNT" ] && SEP=""
            if [ "$TLS" = "true" ]; then
                cat >> $CONF_FILE <<EOF
  {
    "listen": "0.0.0.0:$LPORT",
    "remote": "$RADDR",
    "tls": {
      "enabled": true,
      "insecure": false,
      "ca": "$WORKDIR/$CA_FILENAME"
    },
    "transport": "quic",
    "udp": true,
    "protocol": "shadowsocks",
    "method": "aes-256-gcm",
    "password": "$PW",
    "fast_open": true
  }$SEP
EOF
            else
                cat >> $CONF_FILE <<EOF
  {
    "listen": "0.0.0.0:$LPORT",
    "remote": "$RADDR",
    "tls": {
      "enabled": false
    },
    "transport": "quic",
    "udp": true,
    "protocol": "shadowsocks",
    "method": "aes-256-gcm",
    "password": "$PW",
    "fast_open": true
  }$SEP
EOF
            fi
            IDX=$((IDX+1))
        done < $RULES_FILE
    fi

    echo ']}' >> $CONF_FILE
    echo "配置已同步: $CONF_FILE"
    sleep 1
}

restart_server() {
    is_inited || { echo -e "\e[31m请先初始化配置！\e[0m"; sleep 2; return; }
    gen_conf
    pkill -f "$REALM_BIN.*-c $CONF_FILE" || true
    nohup $REALM_BIN -c $CONF_FILE > $WORKDIR/realm-server.log 2>&1 &
    echo "realm 已重启"
}

restart_client() {
    is_inited || { echo -e "\e[31m请先初始化配置！\e[0m"; sleep 2; return; }
    gen_conf
    pkill -f "$REALM_BIN.*-c $CONF_FILE" || true
    nohup $REALM_BIN -c $CONF_FILE > $WORKDIR/realm-client.log 2>&1 &
    echo "realm 已重启"
}

stop_server() { pkill -f "$REALM_BIN.*-c $CONF_FILE" && echo "服务端已停止" || echo "服务端未运行"; read -p "按回车返回菜单..."; }
stop_client() { pkill -f "$REALM_BIN.*-c $CONF_FILE" && echo "客户端已停止" || echo "客户端未运行"; read -p "按回车返回菜单..."; }
log_server() { tail -n 50 $WORKDIR/realm-server.log || echo "无日志"; read -p "回车返回..."; }
log_client() { tail -n 50 $WORKDIR/realm-client.log || echo "无日志"; read -p "回车返回..."; }

uninstall_realm() {
    pkill -f "$REALM_BIN.*-c $CONF_FILE" || true
    rm -rf $WORKDIR $REALM_BIN
    echo "[√] realm 相关文件和配置均已彻底删除。"
    read -p "按回车返回..."
}

select_role() {
    clear
    echo -e "\033[33m[未检测到已初始化的 realm 服务端或客户端]\033[0m"
    echo "请选择本机角色："
    echo "1) realm 服务端 (出口)"
    echo "2) realm 客户端 (入口)"
    read -p "输入 1 或 2 并回车: " role
    case $role in
        1) echo "server" > $ROLE_FILE ;;
        2) echo "client" > $ROLE_FILE ;;
        *) echo "输入无效，退出"; exit 1 ;;
    esac
}

server_menu() {
    while true; do
        clear
        echo -e "\033[32m==== Nuro · Realm(隧道) 服务端菜单 ====\033[0m"
        echo "1) 一键安装/升级 realm"
        echo "2) 初始化配置并启动"
        echo "3) 添加端口转发规则"
        echo "4) 删除端口转发规则"
        echo "5) 查看所有端口规则"
        echo "6) 重启 realm"
        echo "7) 停止 realm"
        echo "8) 查看服务端日志"
        echo "9) 查看当前转发规则与密码"
        echo "10) 查看当前运行状态"
        echo "11) 启动 CA 拉取服务"
        echo "12) 停止 CA 拉取服务"
        echo "13) 查看/复制 CA 拉取 Token"
        echo "14) 卸载 realm"
        echo "0) 退出"
        echo "-----------------------------"
        read -p "请选择 [0-14]: " choice
        case $choice in
            1) install_realm ;;
            2) init_server ;;
            3) add_rule ;;
            4) del_rule ;;
            5) view_rules ;;
            6) restart_server ;;
            7) stop_server ;;
            8) log_server ;;
            9) show_server_info ;;
            10) server_status ;;
            11) start_ca_server ;;
            12) stop_ca_server ;;
            13) show_ca_token ;;
            14) uninstall_realm ;;
            0) exit 0 ;;
            *) echo "无效选择，重新输入！" && sleep 1 ;;
        esac
    done
}

client_menu() {
    while true; do
        clear
        echo -e "\033[36m==== Nuro · Realm(隧道) 客户端菜单 ====\033[0m"
        echo "1) 一键安装/升级 realm"
        echo "2) 初始化配置并启动"
        echo "3) 添加端口转发规则"
        echo "4) 删除端口转发规则"
        echo "5) 查看所有端口规则"
        echo "6) 重启 realm"
        echo "7) 停止 realm"
        echo "8) 查看客户端日志"
        echo "9) 查看当前运行状态"
        echo "10) 卸载 realm"
        echo "0) 退出"
        echo "-----------------------------"
        read -p "请选择 [0-10]: " choice
        case $choice in
            1) install_realm ;;
            2) init_client ;;
            3) add_rule ;;
            4) del_rule ;;
            5) view_rules ;;
            6) restart_client ;;
            7) stop_client ;;
            8) log_client ;;
            9) client_status ;;
            10) uninstall_realm ;;
            0) exit 0 ;;
            *) echo "无效选择，重新输入！" && sleep 1 ;;
        esac
    done
}

role="$(detect_role)"
case "$role" in
    server) server_menu ;;
    client) client_menu ;;
    *)
        select_role
        role2="$(detect_role)"
        [ "$role2" = "server" ] && server_menu
        [ "$role2" = "client" ] && client_menu
        ;;
esac
