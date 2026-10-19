# Rapport TP04 - Mini-rootkit guide

Toutes les manipulations ont ete effectuees exclusivement sur la VM de test.

## Exercice 1 - DKOM

### Q1 : Captures avant/apres masquage

Avant hide.exe : tasklist | findstr notepad affiche notepad.exe avec son PID. !process 0 0 notepad.exe dans WinDBG montre l'adresse EPROCESS.

Apres hide.exe <pid> : tasklist | findstr notepad ne retourne rien. !process 0 0 notepad.exe dans WinDBG ne trouve plus le processus. Mais !process <adresse_eprocess_notee> 0 montre que notepad tourne toujours.

### Q2 : Visibilite via d'autres mecanismes

- !process 0 0 : utilise ActiveProcessLinks -> processus invisible, affecte par notre manipulation
- dx @$cursession.Processes : selon la version de WinDBG cela peut aussi utiliser ActiveProcessLinks ou croiser d'autres sources. Dans nos tests le processus n'apparait plus non plus.
- !object \Device : independant de ActiveProcessLinks, liste les device objects. Notre processus masque n'a pas de device object associe donc pas visible ici de toute facon.

Conclusion : DKOM ne masque qu'un seul point d'enumeration. Des outils forensiques qui scannent directement le pool de memoire pour trouver des structures EPROCESS (comme Volatility) peuvent detecter le processus masque par incoherence.

### Q3 : Risques

Principal risque : BSOD quand le processus masque se termine. Si on n'a pas fait boucler current->Flink/Blink sur lui-meme, le code de cleanup du noyau (PspExitProcess) tente de retirer l'entree d'une liste dont les pointeurs sont corrompus -> crash. On evite ca en faisant current->Flink = current->Blink = current avant de quitter HideProcess. Autre risque : si une autre structure kernel reference ce EPROCESS et tente de l'enumerer, incoherence possible.

## Exercice 2 - Token Stealing

### Q4 : whoami avant/apres

Dans le cmd cible avant elevate.exe : whoami retourne le nom de l'utilisateur courant (ex: DESKTOP-XXX\user).
Apres elevate.exe <pid_cmd> : whoami dans le meme cmd retourne nt authority\system.

### Q5 : EX_FAST_REF et les 4 bits

Les 4 bits de poids faible d'un pointeur vers un objet kernel sont toujours a 0 car les structures sont alignees sur 16 octets minimum. Microsoft utilise ces bits "gratuits" pour stocker un compteur de reference rapide (RefCnt) sans allocation supplementaire.

Pour la copie : on peut recopier la valeur brute sans masquer les bits, ca fonctionne pour affecter le champ Token d'un autre processus. Le probleme apparait si on tente de dereferenceer ce pointeur brut comme une adresse directe : les 4 bits ajoutent un offset qui pointe a cote de la structure reelle et provoque un acces memoire invalide ou une lecture de donnees incorrectes. Pour acceder au vrai _TOKEN il faut masquer : adresse = valeur & ~0xF.

En pratique pour le token stealing la copie brute suffit et fonctionne. Notre driver copie la valeur brute.

### Q6 : whoami retourne system mais session inchangee

whoami interroge le token du processus courant (OpenProcessToken + GetTokenInformation). On a change le champ Token dans _EPROCESS donc ce token est maintenant celui de System. Tous les appels systeme du processus utilisent desormais ces privileges eleves. Mais la session de bureau (Window Station, Desktop) est un concept completement separe gere par Win32k.sys et winlogon. On n'a touche qu'a la structure process kernel, pas a la session graphique. Donc visuellement la fenetre du cmd reste dans la session utilisateur normale mais les privileges sont SYSTEM.

## Exercice 3 - File Hiding via MiniFilter

### Q7 : dir C:\ avant/apres

Avant chargement du minifilter : dir C:\ montre rootkit_payload.exe, rootkit_config.txt et legitimate_file.txt.
Apres fltmc load HideFiles : dir C:\ ne montre plus que legitimate_file.txt. Les deux fichiers "rootkit" ont disparu.

### Q8 : Tests des limites

- Visible dans l'Explorateur graphique ? Non, meme mecanisme IRP_MJ_DIRECTORY_CONTROL.
- Visible via Get-ChildItem C:\ en PowerShell ? Non, meme chemin d'enumeration.
- Accessible via chemin direct (type C:\rootkit_payload.exe) ? Oui, le minifilter ne filtre que l'enumeration, pas l'ouverture directe par chemin.
- Via NtQueryDirectoryFile direct ? Non, ca passe quand meme par le Filter Manager donc notre filtre intercepte.

La seule vraie limite : un outil qui lit le volume raw directement (acces disque hors ligne) contourne completement le filtrage.

### Q9 : Comparaison DKOM vs minifilter

| | DKOM | Minifilter |
|---|---|---|
| Mecanisme | Manipulation directe de structures non documentees | API officielle Filter Manager |
| Detectabilite | Moins visible (pas de registre de filtres) mais incohérences detectables par scan memoire | Facilement vu via fltmc filters |
| Stabilite | Fragile, risque de BSOD au cleanup | Robuste, API officielle supportee |

## Exercice 4 (bonus) - Rootkit unifie

### Q10 : 3 fonctionnalites supplementaires

1. Persistance : installation du driver avec un nom imitant un service systeme legitime + le minifilter de file hiding cache le .sys dans System32\drivers. Combinaison qui rend le rootkit difficile a decouvrir via l'interface graphique.

2. Masquage reseau : via WFP (Windows Filtering Platform) on peut filtrer les resultats de netstat en interceptant les requetes d'enumeration des connexions TCP actives pour retirer les entrees appartenant au rootkit.

3. Anti-analyse : detection de la presence d'un kernel debugger (KD_DEBUGGER_ENABLED, KdDebuggerNotPresent) et desactivation temporaire des fonctions offensives lors de l'analyse pour echapper a la detection en sandbox/VM de securite.
