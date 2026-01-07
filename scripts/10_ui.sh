#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[10_ui] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STEP00="$ROOT_DIR/scripts/00_env_network.sh"
STEP01="$ROOT_DIR/scripts/01_gateway_forwarding.sh"
STEP02="$ROOT_DIR/scripts/02_start_containers.sh"
STEP03="$ROOT_DIR/scripts/03_hostv_route_back.sh"
STEP04="$ROOT_DIR/scripts/04_cert_setup.sh"
STEP05="$ROOT_DIR/scripts/05_run_server.sh"
STEP06="$ROOT_DIR/scripts/06_run_client.sh"
STEP07="$ROOT_DIR/scripts/07_stop_clean.sh"
STEP08="$ROOT_DIR/scripts/08_capture.sh"
STEP09="$ROOT_DIR/scripts/09_recover.sh"
STEP11="$ROOT_DIR/scripts/11_add_user.sh"

LANG_MODE="${LANG_MODE:-EN}"

if [[ "$EUID" -ne 0 ]]; then
  log "must run as root"
  exit 1
fi

UI="basic"
if command -v whiptail >/dev/null 2>&1; then
  UI="whiptail"
elif command -v dialog >/dev/null 2>&1; then
  UI="dialog"
fi

tr() {
  local key="$1"
  case "$LANG_MODE" in
    ZH)
      case "$key" in
        title) echo "TLS VPN 实验" ;;
        menu) echo "选择操作" ;;
        opt1) echo "初始化网络/容器 (00+01+02+03)" ;;
        opt2) echo "生成证书 (04)" ;;
        opt3) echo "启动服务端 (05)" ;;
        opt4) echo "启动客户端 (06)" ;;
        opt5) echo "断线恢复 (09)" ;;
        opt6) echo "添加本地用户 (11)" ;;
        opt7) echo "抓包 (08)" ;;
        opt8) echo "停止/清理 (07)" ;;
        opt9) echo "语言/Language (当前: 中文)" ;;
        opt10) echo "退出" ;;
        select) echo "请选择操作:" ;;
        extra_title) echo "额外客户端" ;;
        extra_prompt) echo "额外 HostU 列表（name:ip ...），留空跳过:" ;;
        cert_name_title) echo "证书姓名" ;;
        cert_name_prompt) echo "姓名（CERT_NAME）:" ;;
        cert_id_title) echo "证书学号" ;;
        cert_id_prompt) echo "学号（CERT_ID）:" ;;
        cert_email_title) echo "证书邮箱" ;;
        cert_email_prompt) echo "邮箱（可选）:" ;;
        force_title) echo "强制" ;;
        force_prompt) echo "是否强制重新生成？(是/否):" ;;
        client_title) echo "客户端容器" ;;
        client_prompt) echo "客户端容器名:" ;;
        user_title) echo "VPN 用户名" ;;
        user_prompt) echo "VPN 用户名:" ;;
        pass_title) echo "VPN 口令" ;;
        pass_prompt) echo "VPN 口令:" ;;
        add_user_title) echo "添加用户" ;;
        add_user_name) echo "新用户名:" ;;
        add_user_pass) echo "新口令:" ;;
        add_user_sudo) echo "加入 sudo 组？(是/否):" ;;
        cap_iface_title) echo "抓包接口" ;;
        cap_iface_prompt) echo "接口（docker1/docker2/tun0）:" ;;
        cap_port_title) echo "抓包端口" ;;
        cap_port_prompt) echo "端口（可选）:" ;;
        cap_net_title) echo "抓包网段" ;;
        cap_net_prompt) echo "网段过滤（可选）:" ;;
        purge_title) echo "清理" ;;
        purge_prompt) echo "是否清理容器/网络？(是/否):" ;;
        *)
          echo "$key"
          ;;
      esac
      ;;
    *)
      case "$key" in
        title) echo "TLS VPN Lab" ;;
        menu) echo "Select action" ;;
        opt1) echo "Setup networks/containers (00+01+02+03)" ;;
        opt2) echo "Generate certificates (04)" ;;
        opt3) echo "Start server (05)" ;;
        opt4) echo "Start client (06)" ;;
        opt5) echo "Recover after break (09)" ;;
        opt6) echo "Add local user (11)" ;;
        opt7) echo "Start capture (08)" ;;
        opt8) echo "Stop/Clean (07)" ;;
        opt9) echo "Language/语言 (current: English)" ;;
        opt10) echo "Exit" ;;
        select) echo "Select action:" ;;
        extra_title) echo "Extra Clients" ;;
        extra_prompt) echo "Extra HostU list (name:ip ...), blank to skip:" ;;
        cert_name_title) echo "Cert Name" ;;
        cert_name_prompt) echo "Personal name (CERT_NAME):" ;;
        cert_id_title) echo "Cert ID" ;;
        cert_id_prompt) echo "Student ID (CERT_ID):" ;;
        cert_email_title) echo "Cert Email" ;;
        cert_email_prompt) echo "Email (optional):" ;;
        force_title) echo "Force" ;;
        force_prompt) echo "Force regenerate? (yes/no):" ;;
        client_title) echo "Client Container" ;;
        client_prompt) echo "Client container name:" ;;
        user_title) echo "VPN Username" ;;
        user_prompt) echo "VPN username:" ;;
        pass_title) echo "VPN Password" ;;
        pass_prompt) echo "VPN password:" ;;
        add_user_title) echo "Add User" ;;
        add_user_name) echo "New username:" ;;
        add_user_pass) echo "New password:" ;;
        add_user_sudo) echo "Add to sudo group? (yes/no):" ;;
        cap_iface_title) echo "Capture Interface" ;;
        cap_iface_prompt) echo "Interface (docker1/docker2/tun0):" ;;
        cap_port_title) echo "Capture Port" ;;
        cap_port_prompt) echo "Port (optional):" ;;
        cap_net_title) echo "Capture Net" ;;
        cap_net_prompt) echo "Net filter (optional):" ;;
        purge_title) echo "Purge" ;;
        purge_prompt) echo "Purge containers/networks? (yes/no):" ;;
        *)
          echo "$key"
          ;;
      esac
      ;;
  esac
}

is_yes() {
  case "$1" in
    yes|y|YES|Yes|true|TRUE|是|对) return 0 ;;
    *) return 1 ;;
  esac
}

default_no() {
  if [[ "$LANG_MODE" == "ZH" ]]; then
    echo "否"
  else
    echo "no"
  fi
}

input_box() {
  local title="$1" prompt="$2" default="${3:-}"
  if [[ "$UI" == "whiptail" ]]; then
    whiptail --title "$title" --inputbox "$prompt" 10 70 "$default" 3>&1 1>&2 2>&3
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$title" --inputbox "$prompt" 10 70 "$default"
  else
    read -r -p "$prompt " default
    echo "$default"
  fi
}

password_box() {
  local title="$1" prompt="$2"
  if [[ "$UI" == "whiptail" ]]; then
    whiptail --title "$title" --passwordbox "$prompt" 10 70 3>&1 1>&2 2>&3
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$title" --passwordbox "$prompt" 10 70
  else
    read -r -s -p "$prompt " pass
    echo
    echo "$pass"
  fi
}

menu_box() {
  if [[ "$UI" == "whiptail" ]]; then
    whiptail --title "$(tr title)" --menu "$(tr menu)" 20 78 10 \
      "1" "$(tr opt1)" \
      "2" "$(tr opt2)" \
      "3" "$(tr opt3)" \
      "4" "$(tr opt4)" \
      "5" "$(tr opt5)" \
      "6" "$(tr opt6)" \
      "7" "$(tr opt7)" \
      "8" "$(tr opt8)" \
      "9" "$(tr opt9)" \
      "10" "$(tr opt10)" 3>&1 1>&2 2>&3
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$(tr title)" --menu "$(tr menu)" 20 78 10 \
      1 "$(tr opt1)" \
      2 "$(tr opt2)" \
      3 "$(tr opt3)" \
      4 "$(tr opt4)" \
      5 "$(tr opt5)" \
      6 "$(tr opt6)" \
      7 "$(tr opt7)" \
      8 "$(tr opt8)" \
      9 "$(tr opt9)" \
      10 "$(tr opt10)"
  else
    echo "1) $(tr opt1)"
    echo "2) $(tr opt2)"
    echo "3) $(tr opt3)"
    echo "4) $(tr opt4)"
    echo "5) $(tr opt5)"
    echo "6) $(tr opt6)"
    echo "7) $(tr opt7)"
    echo "8) $(tr opt8)"
    echo "9) $(tr opt9)"
    echo "10) $(tr opt10)"
    read -r -p "$(tr select) " choice
    echo "$choice"
  fi
}

while true; do
  choice="$(menu_box || true)"
  case "$choice" in
    1)
      "$STEP00"
      "$STEP01"
      extra="$(input_box "$(tr extra_title)" "$(tr extra_prompt)" "")"
      if [[ -n "$extra" ]]; then
        EXTRA_HOSTU="$extra" "$STEP02"
      else
        "$STEP02"
      fi
      "$STEP03"
      ;;
    2)
      cname="$(input_box "$(tr cert_name_title)" "$(tr cert_name_prompt)" "")"
      cid="$(input_box "$(tr cert_id_title)" "$(tr cert_id_prompt)" "")"
      cemail="$(input_box "$(tr cert_email_title)" "$(tr cert_email_prompt)" "")"
      force="$(input_box "$(tr force_title)" "$(tr force_prompt)" "$(default_no)")"
      args=()
      if is_yes "$force"; then
        args+=(--force)
      fi
      CERT_NAME="$cname" CERT_ID="$cid" CERT_EMAIL="$cemail" "$STEP04" "${args[@]}"
      ;;
    3)
      "$STEP05"
      ;;
    4)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      VPN_USER="$user" VPN_PASS="$pass" CLIENT_NAME="$cname" "$STEP06"
      ;;
    5)
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      VPN_USER="$user" VPN_PASS="$pass" "$STEP09"
      ;;
    6)
      nuser="$(input_box "$(tr add_user_title)" "$(tr add_user_name)" "")"
      npass="$(password_box "$(tr add_user_title)" "$(tr add_user_pass)")"
      addsudo="$(input_box "$(tr add_user_title)" "$(tr add_user_sudo)" "$(default_no)")"
      if is_yes "$addsudo"; then
        addsudo="yes"
      else
        addsudo="no"
      fi
      NEW_USER="$nuser" NEW_PASS="$npass" ADD_SUDO="$addsudo" "$STEP11"
      ;;
    7)
      iface="$(input_box "$(tr cap_iface_title)" "$(tr cap_iface_prompt)" "docker1")"
      port="$(input_box "$(tr cap_port_title)" "$(tr cap_port_prompt)" "")"
      net="$(input_box "$(tr cap_net_title)" "$(tr cap_net_prompt)" "")"
      args=(-i "$iface")
      if [[ -n "$port" ]]; then
        args+=(-p "$port")
      fi
      if [[ -n "$net" ]]; then
        args+=(-n "$net")
      fi
      "$STEP08" "${args[@]}"
      ;;
    8)
      purge="$(input_box "$(tr purge_title)" "$(tr purge_prompt)" "$(default_no)")"
      if is_yes "$purge"; then
        "$STEP07" --purge
      else
        "$STEP07"
      fi
      ;;
    9)
      if [[ "$LANG_MODE" == "ZH" ]]; then
        LANG_MODE="EN"
      else
        LANG_MODE="ZH"
      fi
      ;;
    10|*)
      break
      ;;
  esac
done
