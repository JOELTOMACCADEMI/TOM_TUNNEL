# Gestion des protocoles TOM_TUNNEL

## Depuis le VPS

```bash
sudo -i
tom_tunnel
```

Dans le menu principal, choisir `[19] PROTOCOLS ON/OFF`.

Actions du menu :

1. Activer un protocole
2. Désactiver un protocole (les comptes et données restent conservés)
3. Redémarrer
4. Journaux
5. Ports
6. Erreurs
7. Configurer (ouvre uniquement un fichier natif connu et présent, avec sauvegarde préalable)
8. Vérifier les capacités quota / IP / connexions

## Commandes directes

```bash
tom-protocol list
tom-protocol status zivpn
tom-protocol enable zivpn
tom-protocol disable zivpn
tom-protocol restart zivpn
tom-protocol logs zivpn
tom-protocol ports zivpn
tom-protocol errors zivpn
tom-protocol capabilities
tom-protocol capabilities vless
tom-protocol config vless
```

`config vless` édite le fichier Xray partagé `/etc/xray/config.json` si présent. Cette configuration est commune à VLESS, VMess, Trojan, SOCKS et V2RAY-DNS ; toute modification peut donc toucher ces protocoles. Une sauvegarde horodatée est créée avant édition et une configuration JSON/Xray invalide est restaurée. Le redémarrage n'est pas automatique.

La configuration des autres protocoles n'est proposée que lorsqu'un chemin connu unique existe. En cas de plusieurs fichiers possibles ou d'absence de fichier, le gestionnaire refuse l'édition plutôt que de deviner.

## Depuis Telegram / panel Web

Le bot et le panel partagent le même gestionnaire pour l'état, l'activation, la désactivation, le redémarrage, les journaux, les ports et les erreurs. Les détails Telegram affichent aussi les capacités réellement déclarées. L'édition interactive des fichiers reste réservée au terminal VPS.

## Important

Un protocole désactivé ne doit pas arrêter un autre protocole qui partage le même service. Les protocoles Xray partagent un processus Xray : le gestionnaire bloque les comptes du protocole ciblé au lieu d'arrêter Xray.
