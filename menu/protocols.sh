#!/bin/bash
# TOM_TUNNEL — Gestion des protocoles (activer / désactiver / état / redémarrer / journaux / ports / erreurs)
# Backend commun avec le bot Telegram et le panel Web : tom-protocol (protocol_manager.py).
# Désactiver ne supprime AUCUN compte, quota, limite, expiration ni statistique.

GR='\033[32m'; RD='\033[31m'; YL='\033[33m'; CY='\033[36m'; NC='\033[0m'

TP=""
for p in /usr/local/bin/tom-protocol; do [[ -x "$p" ]] && TP="$p"; done
if [[ -z "$TP" ]]; then
  for f in /usr/local/lib/tom_tunnel/protocol_manager.py \
           "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd)/core/lib/protocol_manager.py"; do
    [[ -f "$f" ]] && TP="python3 $f" && break
  done
fi
if [[ -z "$TP" ]]; then
  echo -e "${RD}protocol_manager introuvable. Lancez : bash core/lib/install_engine.sh${NC}"
  read -rp "Entrée pour revenir..." ; exit 1
fi

IDS=(ssh ssh-ws ssh-ssl dropbear vless vmess trojan socks v2raydns slowdns udpcustom zivpn openvpn ohp)

pick() {
  echo ""
  local i=1
  for id in "${IDS[@]}"; do printf "  ${GR}[%02d]${NC} %s\n" "$i" "$id"; i=$((i+1)); done
  read -rp " Numéro du protocole : " n
  [[ "$n" =~ ^[0-9]+$ ]] && (( n>=1 && n<=${#IDS[@]} )) && PID="${IDS[$((n-1))]}" || { PID=""; echo -e "${RD}Choix invalide${NC}"; }
}

while true; do
  clear
  echo -e "${CY}══════════ GESTION DES PROTOCOLES ══════════${NC}"
  $TP list
  echo -e "${CY}────────────────────────────────────────────${NC}"
  echo -e " ${GR}[1]${NC} Activer   ${GR}[2]${NC} Désactiver   ${GR}[3]${NC} Redémarrer"
  echo -e " ${GR}[4]${NC} Journaux  ${GR}[5]${NC} Ports        ${GR}[6]${NC} Erreurs"
  echo -e " ${GR}[7]${NC} Configurer le protocole (fichier natif + sauvegarde)"
  echo -e " ${GR}[8]${NC} Vérifier les capacités quota / IP / connexions"
  echo -e " ${GR}[0]${NC} Retour"
  read -rp " Choix : " c
  case "$c" in
    1) pick; [[ -n "$PID" ]] && $TP enable "$PID" ;;
    2) pick
       if [[ -n "$PID" ]]; then
         read -rp " Désactiver $PID ? Nouvelles connexions refusées, comptes conservés (o/N) : " y
         [[ "$y" =~ ^[oOyY]$ ]] && $TP disable "$PID" || echo "Annulé."
       fi ;;
    3) pick; [[ -n "$PID" ]] && $TP restart "$PID" ;;
    4) pick; [[ -n "$PID" ]] && $TP logs "$PID" --lines 40 ;;
    5) pick; [[ -n "$PID" ]] && $TP ports "$PID" ;;
    6) pick; [[ -n "$PID" ]] && $TP errors "$PID" ;;
    7) pick; [[ -n "$PID" ]] && $TP config "$PID" ;;
    8) pick; [[ -n "$PID" ]] && $TP capabilities "$PID" ;;
    0|"") exit 0 ;;
    *) echo -e "${RD}Choix invalide${NC}" ;;
  esac
  echo ""; read -rp " Entrée pour continuer..." _
done
