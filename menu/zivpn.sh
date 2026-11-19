#!/bin/bash
clear
BLUE='\033[34m'; GREEN='\033[32m'; RED='\033[31m'; NC='\033[0m'
ENGINE="/usr/local/lib/tom_tunnel/zivpn_engine.py"
if [[ ! -f "$ENGINE" ]]; then ENGINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../core/lib" && pwd)/zivpn_engine.py"; fi
run_engine() { python3 "$ENGINE" "$@"; }
menu_zivpn() {
  clear
  echo -e "${BLUE}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓${NC}"
  echo -e "${BLUE}┃                 ZIVPN ACCOUNT MENU              ┃${NC}"
  echo -e "${BLUE}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${NC}"
  echo " [01] Create account"
  echo " [02] Renew account"
  echo " [03] Delete account"
  echo " [04] Account list"
  echo " [00] Back"
  read -rp " Select: " opt
  case "$opt" in
    1|01)
      read -rp "Username: " user
      read -rsp "Password: " pass; echo
      read -rp "Validity (days): " days
      read -rp "Quota (GB, 0=unlimited): " quota
      read -rp "Max IP addresses (0=unlimited): " ips
      read -rp "Max UDP flows (0=unlimited): " conns
      quota=${quota:-0}; ips=${ips:-0}; conns=${conns:-0}
      result=$(run_engine create "$user" "$pass" "$days" --quota "$quota" --ip-limit "$ips" --conn-limit "$conns" 2>&1)
      if [[ $? -eq 0 ]]; then echo -e "${GREEN}$result${NC}"; else echo -e "${RED}$result${NC}"; fi
      read -n 1 -s -r -p "Press any key..."; menu_zivpn ;;
    2|02)
      read -rp "Username: " user; read -rp "Additional days: " days
      result=$(run_engine renew "$user" "$days" 2>&1)
      if [[ $? -eq 0 ]]; then echo -e "${GREEN}$result${NC}"; else echo -e "${RED}$result${NC}"; fi
      read -n 1 -s -r -p "Press any key..."; menu_zivpn ;;
    3|03)
      read -rp "Username: " user
      result=$(run_engine delete "$user" 2>&1)
      if [[ $? -eq 0 ]]; then echo -e "${GREEN}$result${NC}"; else echo -e "${RED}$result${NC}"; fi
      read -n 1 -s -r -p "Press any key..."; menu_zivpn ;;
    4|04)
      run_engine list
      read -n 1 -s -r -p "Press any key..."; menu_zivpn ;;
    0|00) menu ;;
    *) echo -e "${RED}Invalid option${NC}"; sleep 1; menu_zivpn ;;
  esac
}
menu_zivpn
