# TOM_TUNNEL — matrice réelle des quotas et limites

Source de vérité : SQLite (`core/lib/account_engine.py`). Les quotas sont exprimés en GiB (1 GiB = 1024³ octets) ; `0` signifie illimité. Cette matrice est volontairement conservatrice : une fonctionnalité n'est annoncée comme active que si un collecteur et un mécanisme d'application existent dans ce dépôt.

| Protocole | Quota individuel | Limite IP | Connexions simultanées | Méthode / limites |
|---|---:|---:|---:|---|
| SSH TCP | Oui | Oui | Oui | Compteurs d'octets TCP par socket et sessions sshd observées ; fermeture des sessions refusées. Échantillonnage périodique. |
| SSH WebSocket / SSH SSL | Oui, compte SSH sous-jacent | Oui, compte SSH sous-jacent | Oui, compte SSH sous-jacent | Ce sont des transports d'un compte SSH, pas des comptes autonomes. |
| Dropbear | Oui, si lié à un compte Linux/SSH existant | Oui, si session attribuée | Oui, si session attribuée | Le service Dropbear ne possède pas de namespace d'identité distinct dans ce moteur. |
| VLESS | Oui | Conditionnel | Non | API de statistiques Xray ; IP uniquement si l'IP réelle apparaît dans `access.log`. L'API utilisée ne fournit pas un nombre fiable de flux simultanés par utilisateur. |
| VMess | Oui | Conditionnel | Non | Même moteur Xray que VLESS. |
| Trojan | Oui | Conditionnel | Non | Même moteur Xray que VLESS. |
| SOCKS / Shadowsocks | Oui, si statistiques utilisateur Xray activées | Conditionnel | Non | Même moteur Xray ; IP réelle nécessaire. |
| V2RAY-DNS | Oui | Conditionnel | Non | Compte VLESS/Xray ; IP réelle nécessaire. |
| ZiVPN individuel | Oui | Oui, échantillonnée | Oui, flux UDP échantillonnés | Port UDP dédié par compte, compteurs iptables et conntrack ; timer 10 s. Petit dépassement possible entre deux prélèvements. |
| ZiVPN ancien port partagé 5667 | Non | Non | Non | Trafic non attribuable à un utilisateur individuel. |
| SlowDNS / DNSTT | Non | Non | Non | Aucun adaptateur d'identité/compteur par utilisateur dans cette version. |
| UDP Custom | Non | Non | Non | Listener partagé, trafic non attribuable par compte. |
| OpenVPN | Oui* | Oui* | Oui* | Compteurs CLIENT_LIST du status OpenVPN + sessions IP/connexions + déconnexion via management local TCP 127.0.0.1:7505/7506. Nécessite les directives TOM_TUNNEL dans les deux configurations serveur. |
| OHP | Non | Non | Non | Wrapper de transport sans attribution individuelle dans cette version. |

## Règles de sécurité

- Les champs quota/IP/connexions présents dans la base ne prouvent pas à eux seuls que le protocole les applique.
- Les interfaces doivent consulter `tom-protocol capabilities [id]` et ne pas promettre une fonction déclarée `false`.
- Les IP sont des adresses réseau publiques, pas des personnes ni nécessairement des appareils physiques (NAT).
- Les limites Xray de connexions simultanées restent explicitement non prises en charge : ne pas les présenter comme actives.
- Les anciens comptes ZiVPN sur le port partagé 5667 ne sont pas automatiquement migrés.


*OpenVPN :* l'installation TOM_TUNNEL ajoute `status-version 1` et les interfaces de management locales (TCP 7505 et UDP 7506) aux fichiers `server-tcp-1194.conf` et `server-udp-2200.conf`. Sur un serveur déjà installé, ces directives doivent être ajoutées aux deux fichiers puis les services OpenVPN redémarrés. Les ports de management ne doivent jamais être exposés publiquement. Les limites sont appliquées par le collecteur à son prochain passage (environ une minute).
