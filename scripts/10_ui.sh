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

HOSTV_IP="${HOSTV_IP:-192.168.60.101}"
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
        opt4) echo "启动客户端(前台, 06)" ;;
        opt5) echo "启动客户端(后台, 06 -d)" ;;
        opt6) echo "启动多个客户端(后台)" ;;
        opt7) echo "查看服务端证书信息" ;;
        opt8) echo "修改 HostU 时间(证书过期测试)" ;;
        opt9) echo "恢复 HostU 时间(同步宿主机)" ;;
        opt10) echo "HostU -> HostV ping 测试" ;;
        opt11) echo "HostU -> HostV telnet" ;;
        opt12) echo "查看客户端状态(tun0/路由)" ;;
        opt13) echo "断线恢复 (09)" ;;
        opt14) echo "添加本地用户 (11)" ;;
        opt15) echo "抓包 (08)" ;;
        opt16) echo "停止指定客户端" ;;
        opt17) echo "停止/清理 (07)" ;;
        opt18) echo "语言/Language (当前: 中文)" ;;
        opt19) echo "退出" ;;
        select) echo "请选择操作:" ;;
        press_enter) echo "按回车继续" ;;
        extra_title) echo "额外客户端" ;;
        extra_prompt) echo "额外 HostU 列表（name:ip ...），留空跳过:" ;;
        clients_title) echo "多客户端" ;;
        clients_prompt) echo "客户端列表（空格分隔，如 HostU HostU2）:" ;;
        cert_name_title) echo "证书姓名" ;;
        cert_name_prompt) echo "姓名（CERT_NAME）:" ;;
        cert_id_title) echo "证书学号" ;;
        cert_id_prompt) echo "学号（CERT_ID）:" ;;
        cert_email_title) echo "证书邮箱" ;;
        cert_email_prompt) echo "邮箱（可选）:" ;;
        cert_info_title) echo "证书信息" ;;
        force_title) echo "强制" ;;
        force_prompt) echo "是否强制重新生成？(是/否):" ;;
        client_title) echo "客户端容器" ;;
        client_prompt) echo "客户端容器名:" ;;
        user_title) echo "VPN 用户名" ;;
        user_prompt) echo "VPN 用户名:" ;;
        pass_title) echo "VPN 口令" ;;
        pass_prompt) echo "VPN 口令:" ;;
        time_title) echo "HostU 时间" ;;
        time_prompt) echo "设置时间（YYYY-MM-DD HH:MM:SS）:" ;;
        time_reset_title) echo "恢复时间" ;;
        status_title) echo "客户端状态" ;;
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
        opt4) echo "Start client (foreground, 06)" ;;
        opt5) echo "Start client (background, 06 -d)" ;;
        opt6) echo "Start multiple clients (background)" ;;
        opt7) echo "Show server certificate info" ;;
        opt8) echo "Set HostU time (expiry test)" ;;
        opt9) echo "Reset HostU time (sync from host)" ;;
        opt10) echo "HostU -> HostV ping" ;;
        opt11) echo "HostU -> HostV telnet" ;;
        opt12) echo "Show client status (tun0/route)" ;;
        opt13) echo "Recover after break (09)" ;;
        opt14) echo "Add local user (11)" ;;
        opt15) echo "Start capture (08)" ;;
        opt16) echo "Stop client in container" ;;
        opt17) echo "Stop/Clean (07)" ;;
        opt18) echo "Language/语言 (current: English)" ;;
        opt19) echo "Exit" ;;
        select) echo "Select action:" ;;
        press_enter) echo "Press Enter to continue" ;;
        extra_title) echo "Extra Clients" ;;
        extra_prompt) echo "Extra HostU list (name:ip ...), blank to skip:" ;;
        clients_title) echo "Multiple Clients" ;;
        clients_prompt) echo "Client list (space separated, e.g., HostU HostU2):" ;;
        cert_name_title) echo "Cert Name" ;;
        cert_name_prompt) echo "Personal name (CERT_NAME):" ;;
        cert_id_title) echo "Cert ID" ;;
        cert_id_prompt) echo "Student ID (CERT_ID):" ;;
        cert_email_title) echo "Cert Email" ;;
        cert_email_prompt) echo "Email (optional):" ;;
        cert_info_title) echo "Certificate Info" ;;
        force_title) echo "Force" ;;
        force_prompt) echo "Force regenerate? (yes/no):" ;;
        client_title) echo "Client Container" ;;
        client_prompt) echo "Client container name:" ;;
        user_title) echo "VPN Username" ;;
        user_prompt) echo "VPN username:" ;;
        pass_title) echo "VPN Password" ;;
        pass_prompt) echo "VPN password:" ;;
        time_title) echo "HostU Time" ;;
        time_prompt) echo "Set time (YYYY-MM-DD HH:MM:SS):" ;;
        time_reset_title) echo "Reset Time" ;;
        status_title) echo "Client Status" ;;
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

pause_box() {
  if [[ "$UI" == "whiptail" ]]; then
    whiptail --title "$(tr title)" --msgbox "$(tr press_enter)" 8 60
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$(tr title)" --msgbox "$(tr press_enter)" 8 60
  else
    read -r -p "$(tr press_enter) " _
  fi
}

ensure_container() {
  local name="$1"
  docker start "$name" >/dev/null 2>&1 || true
}

show_output() {
  local title="$1"
  shift
  local tmp
  tmp="$(mktemp)"
  if ! "$@" >"$tmp" 2>&1; then
    echo "command failed" >>"$tmp"
  fi
  if [[ "$UI" == "whiptail" ]]; then
    whiptail --title "$title" --textbox "$tmp" 20 78
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$title" --textbox "$tmp" 20 78
  else
    cat "$tmp"
    pause_box
  fi
  rm -f "$tmp"
}

run_interactive() {
  if [[ "$UI" == "whiptail" || "$UI" == "dialog" ]]; then
    clear
  fi
  "$@" || true
  pause_box
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
    whiptail --title "$(tr title)" --menu "$(tr menu)" 24 90 19 \
      "1" "$(tr opt1)" \
      "2" "$(tr opt2)" \
      "3" "$(tr opt3)" \
      "4" "$(tr opt4)" \
      "5" "$(tr opt5)" \
      "6" "$(tr opt6)" \
      "7" "$(tr opt7)" \
      "8" "$(tr opt8)" \
      "9" "$(tr opt9)" \
      "10" "$(tr opt10)" \
      "11" "$(tr opt11)" \
      "12" "$(tr opt12)" \
      "13" "$(tr opt13)" \
      "14" "$(tr opt14)" \
      "15" "$(tr opt15)" \
      "16" "$(tr opt16)" \
      "17" "$(tr opt17)" \
      "18" "$(tr opt18)" \
      "19" "$(tr opt19)" 3>&1 1>&2 2>&3
  elif [[ "$UI" == "dialog" ]]; then
    dialog --stdout --title "$(tr title)" --menu "$(tr menu)" 24 90 19 \
      1 "$(tr opt1)" \
      2 "$(tr opt2)" \
      3 "$(tr opt3)" \
      4 "$(tr opt4)" \
      5 "$(tr opt5)" \
      6 "$(tr opt6)" \
      7 "$(tr opt7)" \
      8 "$(tr opt8)" \
      9 "$(tr opt9)" \
      10 "$(tr opt10)" \
      11 "$(tr opt11)" \
      12 "$(tr opt12)" \
      13 "$(tr opt13)" \
      14 "$(tr opt14)" \
      15 "$(tr opt15)" \
      16 "$(tr opt16)" \
      17 "$(tr opt17)" \
      18 "$(tr opt18)" \
      19 "$(tr opt19)"
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
    echo "11) $(tr opt11)"
    echo "12) $(tr opt12)"
    echo "13) $(tr opt13)"
    echo "14) $(tr opt14)"
    echo "15) $(tr opt15)"
    echo "16) $(tr opt16)"
    echo "17) $(tr opt17)"
    echo "18) $(tr opt18)"
    echo "19) $(tr opt19)"
    read -r -p "$(tr select) " choice
    echo "$choice"
  fi
}

while true; do
  choice="$(menu_box || true)"
  case "$choice" in
    1)
      if ! "$STEP00"; then
        pause_box
        continue
      fi
      if ! "$STEP01"; then
        pause_box
        continue
      fi
      extra="$(input_box "$(tr extra_title)" "$(tr extra_prompt)" "")"
      if [[ -n "$extra" ]]; then
        if ! EXTRA_HOSTU="$extra" "$STEP02"; then
          pause_box
          continue
        fi
      else
        if ! "$STEP02"; then
          pause_box
          continue
        fi
      fi
      if ! "$STEP03"; then
        pause_box
        continue
      fi
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
      if ! CERT_NAME="$cname" CERT_ID="$cid" CERT_EMAIL="$cemail" "$STEP04" "${args[@]}"; then
        pause_box
      fi
      ;;
    3)
      if ! "$STEP05"; then
        pause_box
      fi
      ;;
    4)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      if [[ -z "$user" || -z "$pass" ]]; then
        log "VPN user/pass required"
        pause_box
      elif ! VPN_USER="$user" VPN_PASS="$pass" CLIENT_NAME="$cname" "$STEP06"; then
        pause_box
      fi
      ;;
    5)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      if [[ -z "$user" || -z "$pass" ]]; then
        log "VPN user/pass required"
        pause_box
      elif ! VPN_USER="$user" VPN_PASS="$pass" CLIENT_NAME="$cname" "$STEP06" -d; then
        pause_box
      fi
      ;;
    6)
      list="$(input_box "$(tr clients_title)" "$(tr clients_prompt)" "")"
      if [[ -z "$list" ]]; then
        log "client list required"
        pause_box
        continue
      fi
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      if [[ -z "$user" || -z "$pass" ]]; then
        log "VPN user/pass required"
        pause_box
        continue
      fi
      for cname in $list; do
        if ! VPN_USER="$user" VPN_PASS="$pass" CLIENT_NAME="$cname" "$STEP06" -d; then
          log "client $cname failed"
        fi
      done
      pause_box
      ;;
    7)
      if [[ -f "$ROOT_DIR/cert/server.crt" ]]; then
        show_output "$(tr cert_info_title)" openssl x509 -in "$ROOT_DIR/cert/server.crt" -noout -subject -issuer -dates
      else
        log "cert/server.crt not found"
        pause_box
      fi
      ;;
    8)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      tstr="$(input_box "$(tr time_title)" "$(tr time_prompt)" "2038-01-01 00:00:00")"
      if [[ -n "$tstr" ]]; then
        ensure_container "$cname"
        show_output "$(tr time_title)" docker exec "$cname" date -s "$tstr"
      fi
      ;;
    9)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      ensure_container "$cname"
      host_time="$(date '+%Y-%m-%d %H:%M:%S')"
      show_output "$(tr time_reset_title)" docker exec "$cname" date -s "$host_time"
      ;;
    10)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      ensure_container "$cname"
      run_interactive docker exec -it "$cname" ping -c 3 "$HOSTV_IP"
      ;;
    11)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      ensure_container "$cname"
      run_interactive docker exec -it "$cname" telnet "$HOSTV_IP"
      ;;
    12)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      ensure_container "$cname"
      show_output "$(tr status_title)" docker exec "$cname" sh -c "ip addr show dev tun0; echo; ip route show | grep 192.168.60.0/24 || true"
      ;;
    13)
      user="$(input_box "$(tr user_title)" "$(tr user_prompt)" "")"
      pass="$(password_box "$(tr pass_title)" "$(tr pass_prompt)")"
      if [[ -z "$user" || -z "$pass" ]]; then
        log "VPN user/pass required"
        pause_box
      elif ! VPN_USER="$user" VPN_PASS="$pass" "$STEP09"; then
        pause_box
      fi
      ;;
    14)
      nuser="$(input_box "$(tr add_user_title)" "$(tr add_user_name)" "")"
      npass="$(password_box "$(tr add_user_title)" "$(tr add_user_pass)")"
      addsudo="$(input_box "$(tr add_user_title)" "$(tr add_user_sudo)" "$(default_no)")"
      if is_yes "$addsudo"; then
        addsudo="yes"
      else
        addsudo="no"
      fi
      if ! NEW_USER="$nuser" NEW_PASS="$npass" ADD_SUDO="$addsudo" "$STEP11"; then
        pause_box
      fi
      ;;
    15)
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
      if ! "$STEP08" "${args[@]}"; then
        pause_box
      fi
      ;;
    16)
      cname="$(input_box "$(tr client_title)" "$(tr client_prompt)" "HostU")"
      ensure_container "$cname"
      log "stopping vpnclient in $cname"
      docker exec "$cname" pkill vpnclient >/dev/null 2>&1 || true
      docker exec "$cname" ip link del tun0 >/dev/null 2>&1 || true
      docker exec "$cname" ip route del 192.168.60.0/24 >/dev/null 2>&1 || true
      pause_box
      ;;
    17)
      purge="$(input_box "$(tr purge_title)" "$(tr purge_prompt)" "$(default_no)")"
      if is_yes "$purge"; then
        if ! "$STEP07" --purge; then
          pause_box
        fi
      else
        if ! "$STEP07"; then
          pause_box
        fi
      fi
      ;;
    18)
      if [[ "$LANG_MODE" == "ZH" ]]; then
        LANG_MODE="EN"
      else
        LANG_MODE="ZH"
      fi
      ;;
    19|*)
      break
      ;;
  esac
done
