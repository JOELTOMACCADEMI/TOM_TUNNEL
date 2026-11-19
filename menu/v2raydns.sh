#!/bin/bash
# TOM_TUNNEL — V2RAY-DNS module
# Combines VLESS/Trojan (Xray) account management with DNS tunnel parameters
# (NS domain, SlowDNS pubkey) when available. Does NOT invent fake link formats.
#
# Modes actually supported:
#   1) VLESS over TCP/WS/gRPC (standard Xray) + optional DNS metadata for clients
#   2) Trojan over TCP/WS/gRPC (standard Xray) + optional DNS metadata
#   3) Display of existing SlowDNS/NS parameters for dual-stack clients
#
# A pure "DNS-only V2Ray transport" is NOT claimed unless dnstt/slowdns
# infrastructure is already installed on the host.

clear
export LN='\033[34m'
export BG='\033[44m'
export NC='\033[0m'
export GR='\033[32m'
export RD='\033[31m'
export YL='\033[33m'

DOMAIN=$(cat /etc/xray/domain 2>/dev/null || echo "N/A")
MYIP=$(wget -qO- ipv4.icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
PUB=$(cat /etc/slowdns/server.pub 2>/dev/null || echo "N/A")
NSDOMAIN=$(cat /etc/slowdns/nsdomain 2>/dev/null || echo "N/A")
XRAY_CONF="/etc/xray/config.json"
ENGINE=""
for p in /usr/local/lib/tom_tunnel/account_engine.py \
         "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/core/lib/account_engine.py"; do
  [[ -f "$p" ]] && ENGINE="$p" && break
done

_engine_create() {
  local user="$1" proto="$2" days="$3" quota="$4" ipl="$5" connl="$6"
  [[ -z "$ENGINE" ]] && return 0
  python3 "$ENGINE" create "$user" "$proto" --days "$days" \
    --quota "$quota" --ip-limit "$ipl" --conn-limit "$connl" >/dev/null 2>&1 || true
}

_pause() {
  echo ""
  read -n 1 -s -r -p "  Press any key to return..."
  v2raydns
}

_header() {
  clear
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} ${BG}              V2RAY-DNS MODULE                  ${NC} ${LN}┃${NC}"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

_show_dns_info() {
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} Domain       : ${DOMAIN}"
  echo -e "${LN}┃${NC} Server IP    : ${MYIP}"
  echo -e "${LN}┃${NC} NS Domain    : ${NSDOMAIN}"
  echo -e "${LN}┃${NC} SlowDNS PUB  : ${PUB}"
  echo -e "${LN}┃${NC}"
  if [[ "$PUB" == "N/A" || "$NSDOMAIN" == "N/A" ]]; then
    echo -e "${LN}┃${NC} ${YL}[INFO] SlowDNS not fully configured.${NC}"
    echo -e "${LN}┃${NC} ${YL}      VLESS/Trojan TCP still work normally.${NC}"
    echo -e "${LN}┃${NC} ${YL}      Install SlowDNS from menu [07]/[16] if needed.${NC}"
  else
    echo -e "${LN}┃${NC} ${GR}[OK] DNS tunnel parameters available.${NC}"
  fi
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
}

add_v2raydns_vless() {
  _header
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} ${BG}         ADD VLESS (V2RAY-DNS context)          ${NC} ${LN}┃${NC}"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  _show_dns_info
  echo ""
  while true; do
    read -rp "  Username: " user
    [[ -z "$user" ]] && echo -e " ${RD}Empty username.${NC}" && continue
    [[ ! "$user" =~ ^[a-zA-Z0-9_]+$ ]] && echo -e " ${RD}Invalid chars.${NC}" && continue
    if grep -qw "$user" "$XRAY_CONF" 2>/dev/null; then
      echo -e " ${RD}Username already exists.${NC}"; continue
    fi
    break
  done
  while true; do
    read -rp "  Validity (days): " days
    [[ "$days" =~ ^[0-9]+$ && "$days" -gt 0 ]] && break
    echo -e " ${RD}Positive number required.${NC}"
  done
  read -rp "  Quota (GB, 0=unlimited): " QuotaGB; QuotaGB=${QuotaGB:-0}
  read -rp "  IP Limit (0=unlimited): " IpLimit; IpLimit=${IpLimit:-0}
  read -rp "  Conn Limit (0=unlimited): " ConnLimit; ConnLimit=${ConnLimit:-0}

  uuid=$(cat /proc/sys/kernel/random/uuid)
  exp=$(date -d "+$days days" +"%Y-%m-%d")

  if [[ -f "$XRAY_CONF" ]]; then
    sed -i '/#vless$/a\#& '"$user $exp $uuid"'\
},{"id": "'"$uuid"'","email": "'"$user"'"' "$XRAY_CONF" 2>/dev/null || true
    sed -i '/#vlessgrpc$/a\#& '"$user $exp $uuid"'\
},{"id": "'"$uuid"'","email": "'"$user"'"' "$XRAY_CONF" 2>/dev/null || true
    systemctl restart xray >/dev/null 2>&1 || true
  fi

  _engine_create "$user" "vless" "$days" "$QuotaGB" "$IpLimit" "$ConnLimit"

  link_tls="vless://${uuid}@${DOMAIN}:443?path=/vless&security=tls&encryption=none&type=ws#${user}"
  link_ntls="vless://${uuid}@${DOMAIN}:80?path=/vless&encryption=none&type=ws#${user}"
  link_grpc="vless://${uuid}@${DOMAIN}:443?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc#${user}"

  clear
  _header
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} Username    : ${user}"
  echo -e "${LN}┃${NC} UUID        : ${uuid}"
  echo -e "${LN}┃${NC} Expiry      : ${exp}"
  echo -e "${LN}┃${NC} Quota       : ${QuotaGB} GB"
  echo -e "${LN}┃${NC} IP Limit    : ${IpLimit}"
  echo -e "${LN}┃${NC} Conn Limit  : ${ConnLimit}"
  echo -e "${LN}┃${NC} Domain      : ${DOMAIN}"
  echo -e "${LN}┃${NC} NS Domain   : ${NSDOMAIN}"
  echo -e "${LN}┃${NC} SlowDNS PUB : ${PUB}"
  echo -e "${LN}●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━●${NC}"
  echo -e "${LN}┃${NC} VLESS WS TLS :"
  echo -e "${LN}┃${NC} ${link_tls}"
  echo -e "${LN}┃${NC} VLESS WS NTLS:"
  echo -e "${LN}┃${NC} ${link_ntls}"
  echo -e "${LN}┃${NC} VLESS gRPC   :"
  echo -e "${LN}┃${NC} ${link_grpc}"
  echo -e "${LN}●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━●${NC}"
  echo -e "${LN}┃${NC} ${YL}Note: Links above are standard VLESS TCP/WS/gRPC.${NC}"
  echo -e "${LN}┃${NC} ${YL}DNS metadata (NS/PUB) is for dual-stack clients${NC}"
  echo -e "${LN}┃${NC} ${YL}that also use SlowDNS (e.g. HTTP Custom / ZIVPN).${NC}"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  _pause
}

add_v2raydns_trojan() {
  _header
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} ${BG}        ADD TROJAN (V2RAY-DNS context)          ${NC} ${LN}┃${NC}"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  _show_dns_info
  echo ""
  while true; do
    read -rp "  Username: " user
    [[ -z "$user" ]] && continue
    [[ ! "$user" =~ ^[a-zA-Z0-9_]+$ ]] && echo -e " ${RD}Invalid.${NC}" && continue
    if grep -qw "$user" "$XRAY_CONF" 2>/dev/null; then
      echo -e " ${RD}Exists.${NC}"; continue
    fi
    break
  done
  while true; do
    read -rp "  Password: " pass
    [[ -n "$pass" ]] && break
  done
  while true; do
    read -rp "  Validity (days): " days
    [[ "$days" =~ ^[0-9]+$ && "$days" -gt 0 ]] && break
  done
  read -rp "  Quota (GB, 0=unlimited): " QuotaGB; QuotaGB=${QuotaGB:-0}
  read -rp "  IP Limit (0=unlimited): " IpLimit; IpLimit=${IpLimit:-0}
  read -rp "  Conn Limit (0=unlimited): " ConnLimit; ConnLimit=${ConnLimit:-0}

  exp=$(date -d "+$days days" +"%Y-%m-%d")
  if [[ -f "$XRAY_CONF" ]]; then
    sed -i '/#trojanws$/a\#! '"$user $exp $pass"'\
},{"password": "'"$pass"'","email": "'"$user"'"' "$XRAY_CONF" 2>/dev/null || true
    sed -i '/#trojangrpc$/a\#! '"$user $exp $pass"'\
},{"password": "'"$pass"'","email": "'"$user"'"' "$XRAY_CONF" 2>/dev/null || true
    systemctl restart xray >/dev/null 2>&1 || true
  fi
  _engine_create "$user" "trojan" "$days" "$QuotaGB" "$IpLimit" "$ConnLimit"

  link_ws="trojan://${pass}@${DOMAIN}:443?path=/trws&security=tls&type=ws#${user}"
  link_grpc="trojan://${pass}@${DOMAIN}:443?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc#${user}"

  clear
  _header
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} Username    : ${user}"
  echo -e "${LN}┃${NC} Password    : ${pass}"
  echo -e "${LN}┃${NC} Expiry      : ${exp}"
  echo -e "${LN}┃${NC} Quota       : ${QuotaGB} GB"
  echo -e "${LN}┃${NC} IP / Conn   : ${IpLimit} / ${ConnLimit}"
  echo -e "${LN}┃${NC} Domain      : ${DOMAIN}"
  echo -e "${LN}┃${NC} NS / PUB    : ${NSDOMAIN} / ${PUB}"
  echo -e "${LN}●━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━●${NC}"
  echo -e "${LN}┃${NC} Trojan WS  : ${link_ws}"
  echo -e "${LN}┃${NC} Trojan gRPC: ${link_grpc}"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  _pause
}

show_status() {
  _header
  _show_dns_info
  echo ""
  if systemctl is-active --quiet xray 2>/dev/null; then
    echo -e "  ${GR}● Xray: ONLINE${NC}"
  else
    echo -e "  ${RD}● Xray: OFFLINE${NC}"
  fi
  if systemctl is-active --quiet client-sldns 2>/dev/null || systemctl is-active --quiet server-sldns 2>/dev/null; then
    echo -e "  ${GR}● SlowDNS service: detected active${NC}"
  else
    echo -e "  ${YL}● SlowDNS service: not detected (optional)${NC}"
  fi
  if [[ -n "$ENGINE" ]]; then
    echo -e "  ${GR}● Account engine: available${NC}"
  else
    echo -e "  ${YL}● Account engine: not installed on PATH${NC}"
  fi
  _pause
}

# ─── Main menu ───────────────────────────────────────────────────────────────
v2raydns() {
  _header
  _show_dns_info
  echo -e "${LN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${LN}┃${NC} [01] • Create VLESS account (+ DNS metadata)"
  echo -e "${LN}┃${NC} [02] • Create Trojan account (+ DNS metadata)"
  echo -e "${LN}┃${NC} [03] • Show DNS / service status"
  echo -e "${LN}┃${NC} [00] • Back to main menu"
  echo -e "${LN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo ""
  read -rp " Select option: " opt
  case $opt in
    1|01) add_v2raydns_vless ;;
    2|02) add_v2raydns_trojan ;;
    3|03) show_status ;;
    0|00) menu ;;
    *) v2raydns ;;
  esac
}

v2raydns
