# Rapport de conception — Rootkit-2600
**École 2600 — Cybersécurité — Promotion 2026**

---

## 1. Présentation du projet

Rootkit-2600 est un module kernel Linux développé à des fins pédagogiques dans le cadre du cours de sécurité offensive. Il implémente les fonctionnalités classiques d'un rootkit noyau : escalade de privilèges, dissimulation de processus, de fichiers, de ports réseau, et persistance au redémarrage.

L'ensemble du projet s'exécute dans une machine virtuelle QEMU isolée, construite automatiquement via un script Docker/loopback produisant une image qcow2 bootable sous Alpine Linux.

---

## 2. Architecture technique

Le rootkit est structuré en modules indépendants compilés en tant que module kernel (`rootkit.ko`) :

| Fichier | Rôle |
|---|---|
| `get_root.c` | Point d'entrée, interface `/proc/root`, escalade de privilèges |
| `hide.c` | Dissimulation du module dans la liste `lsmod` |
| `hide_file.c` | Hook `getdents64` via kretprobe pour cacher fichiers et processus |
| `hide_net.c` | Hook `tcp4_seq_show` via kretprobe pour cacher les ports TCP |
| `persistence.c` | Écriture dans `/etc/inittab` et `/etc/crontabs/root` au chargement |
| `companion.c` | Outil userspace communiquant via `/proc/root` |

Les hooks noyau utilisent l'infrastructure **kretprobe** (Linux 6.x) plutôt que le patch direct de la syscall table, incompatible avec `CONFIG_STRICT_KERNEL_RWX` des kernels récents.

---

## 3. Répartition des tâches

### Tableau des contributions

### Détail des contributions

**Matthieu Da Cruz** a conçu la structure générale du module kernel, implémenté la fonction d'escalade de privilèges (`grant_root`) via `prepare_creds`/`commit_creds`, et développé l'interface de commande `/proc/root` permettant de piloter toutes les fonctionnalités depuis l'espace utilisateur.

**Thomas Fedorawiez** a implémenté la dissimulation de fichiers et de processus en hookant l'appel système `getdents64` via kretprobe. Le hook filtre dynamiquement les entrées du buffer de répertoire avant leur retour à l'espace utilisateur. Il a également implémenté la dissimulation du module lui-même en le retirant de la liste chaînée des modules kernel.

**Nicolas Judith** a implémenté la dissimulation des connexions TCP en hookant la fonction `tcp4_seq_show` via kretprobe. La technique consiste à sauvegarder la position d'écriture du buffer seq_file avant l'appel et à la restaurer si la connexion correspond au port caché, annulant ainsi l'écriture sans modifier de mémoire en lecture seule.

**Ayoub el-yhadini** a développé le mécanisme de persistance au redémarrage (écriture dans `/etc/inittab` et `/etc/crontabs/root` via `kernel_write` + `vfs_fsync`), créé le script `build_image.sh` automatisant la construction de l'image QEMU bootable, et rédigé la documentation technique.

---

## 4. Scénarios d'accès initial (Bonus)

### Contexte

Le chargement d'un module kernel non signé nécessite que le système cible ne dispose pas de **Secure Boot** actif ou que la vérification de signature des modules (`CONFIG_MODULE_SIG_FORCE`) soit désactivée. Voici des domaines industriels réalistes où cette condition est fréquemment rencontrée.

---

### Scénario 1 — Systèmes embarqués industriels (ICS/SCADA)

**Domaine :** Industrie manufacturière, énergie, traitement des eaux, automates.

**Contexte :** Les contrôleurs industriels (PLC, RTU) et les systèmes SCADA tournent souvent sur des Linux embarqués compilés sur mesure par les équipementiers (Siemens, Schneider Electric, ABB). Ces kernels sont buildés sans signature de modules pour des raisons de compatibilité avec des drivers propriétaires non maintenus ou des contraintes temps-réel.

**Vecteur d'accès initial :**
- Exploitation d'une interface web de supervision exposée sur le réseau OT (CVE récurrentes sur les interfaces HMI)
- Credential stuffing sur des comptes SSH laissés avec les mots de passe par défaut constructeur
- Attaque de la chaîne d'approvisionnement via la mise à jour firmware

**Pourquoi le module n'est pas signé :** Cycle de vie long (10-20 ans), kernel figé à une version ancienne (< 3.7 pour certains), absence de mise à jour de sécurité, Secure Boot non supporté par le matériel.

---

### Scénario 2 — Appliances réseau et firewalls d'entrée de gamme

**Domaine :** PME, collectivités territoriales, routeurs/firewalls low-cost.

**Contexte :** Les appliances réseau bas de gamme (certains modèles pfSense sur hardware générique, routeurs industriels 4G, VPN concentrators) tournent sur Linux avec des modules réseau propriétaires (drivers Wi-Fi, accélérateurs crypto) non signés.

**Vecteur d'accès initial :**
- Exploitation de l'interface d'administration web (injections de commandes, path traversal)
- Vulnérabilité dans le daemon VPN (ex : type confusion dans le parseur IKEv2)
- Scan Shodan des interfaces d'admin exposées sur Internet avec authentification faible

**Pourquoi le module n'est pas signé :** Éditeur indépendant qui distribue des `.ko` précompilés pour plusieurs versions de kernel sans infrastructure de signature, ou module tiers non soumis au processus de review Linux upstream.

---

### Scénario 3 — Serveurs de développement et CI/CD

**Domaine :** Startups tech, équipes DevOps, laboratoires universitaires.

**Contexte :** Les runners CI/CD (GitLab Runner, Jenkins) tournent souvent sur des VM Linux avec des kernels génériques Ubuntu/Debian où Secure Boot est désactivé pour simplifier l'installation de drivers NVIDIA ou de modules DKMS. Les équipes de développement désactivent fréquemment les contraintes de sécurité pour faciliter le débogage.

**Vecteur d'accès initial :**
- Compromission d'un pipeline CI/CD via un dépôt de dépendance malveillant (supply chain)
- RCE dans un service exposé sur le réseau interne (Jenkins, GitLab CE non patché)
- Vol de token d'accès via un `.env` commité par erreur dans un repo public

**Pourquoi le module n'est pas signé :** `GRUB_CMDLINE_LINUX="... module.sig_enforce=0"` mis en place par un développeur pour charger un module DKMS maison, jamais révoqué. Secure Boot désactivé dans le BIOS pour "aller plus vite".

---

### Synthèse

| Domaine | Raison technique de l'absence de signature | Probabilité de rencontre |
|---|---|---|
| ICS/SCADA industriel | Kernel ancien, hardware sans Secure Boot | Élevée |
| Appliances réseau | Modules propriétaires tiers non signés | Moyenne |
| Serveurs CI/CD | Secure Boot désactivé volontairement | Élevée |

Dans tous ces scénarios, l'attaquant disposant d'un accès root (ou d'une vulnérabilité locale permettant l'escalade) peut charger `rootkit.ko` directement avec `insmod`, sans aucune contrainte de signature.

---

*Rapport rédigé dans le cadre du module Sécurité Offensive — École 2600 — 2026*
