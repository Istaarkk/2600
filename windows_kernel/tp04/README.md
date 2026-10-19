# TP04 — Rootkit techniques (VM uniquement)

> Ces techniques sont à des fins éducatives uniquement.
> Elles doivent être réalisées exclusivement sur votre VM de test.

## Prérequis

- VM isolée, snapshot propre
- testsigning activé, WDK installé
- Les offsets EPROCESS ci-dessous sont valides pour Windows 10/11 builds récents.
  Vérifier avec WinDBG si nécessaire :
  ```
  dt nt!_EPROCESS
  ```

Offsets utilisés dans le code :

| Champ               | Offset |
|---------------------|--------|
| UniqueProcessId     | 0x440  |
| ActiveProcessLinks  | 0x448  |
| Token               | 0x4b8  |
| ImageFileName       | 0x5a8  |

---

## dkom — Masquage de processus

### Compilation

Projet Driver (WDM) :
- Sources : `dkom.c`, `dkom.h`
- Résultat : `dkom.sys`

Client :
- Sources : `hide.c`, `dkom.h`
- Résultat : `hide.exe`

### Utilisation

```cmd
sc create Dkom type= kernel binPath= C:\path\to\dkom.sys
sc start Dkom

hide.exe 1234
```

Le processus PID 1234 disparaît de la liste retournée par `tasklist`, Process Hacker, etc.

Note : le processus continue de s'exécuter. `current->Flink = current->Blink = current` permet au processus de se terminer proprement sans BSOD.

---

## steal — Vol de token SYSTEM

### Compilation

Projet Driver (WDM) :
- Sources : `steal.c`, `steal.h`
- Résultat : `steal.sys`

Client :
- Sources : `elevate.c`, `steal.h`
- Résultat : `elevate.exe`

### Utilisation

```cmd
sc create Steal type= kernel binPath= C:\path\to\steal.sys
sc start Steal

elevate.exe <pid_de_cmd.exe>
```

Le processus ciblé hérite du token SYSTEM (PID 4). Ouvrir une nouvelle fenêtre depuis ce processus → `whoami` retourne `NT AUTHORITY\SYSTEM`.

---

## hidefiles — Masquage de fichiers

### Compilation

Projet MiniFilter Driver :
- Sources : `hidefiles.c`
- Résultat : `hidefiles.sys`

### Installation

Importer `hidefiles.reg` ou créer la clé manuellement (altitude 370000, groupe FSFilter Activity Monitor).

```cmd
fltmc load HideFiles
```

### Test

Créer un fichier dont le nom contient "rootkit" :
```cmd
echo test > C:\temp\rootkit_test.txt
dir C:\temp
```

Le fichier n'apparaît pas dans le listing — mais il existe toujours sur disque (vérifiable en y accédant directement par son chemin complet).

### Déchargement

```cmd
fltmc unload HideFiles
```
