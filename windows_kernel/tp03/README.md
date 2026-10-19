# TP03 — Callbacks noyau

## Prérequis

- VM avec testsigning activé
- WDK installé, Visual Studio 2022

---

## procmon — Moniteur de processus

### Compilation

Projet Driver (WDM) :
- Sources : `procmon.c`
- **Important** : ajouter `/INTEGRITYCHECK` dans les options de l'éditeur de liens (Linker → Command Line → Additional Options)
  Sans ce flag, `PsSetCreateProcessNotifyRoutineEx` retourne `STATUS_ACCESS_DENIED`
- Résultat : `procmon.sys`

### Chargement

```cmd
sc create ProcMon type= kernel binPath= C:\path\to\procmon.sys
sc start ProcMon
```

Lancer DebugView en tant qu'administrateur. Ouvrir/fermer des applications — chaque création et terminaison de processus apparaît dans DebugView :
```
ProcMon: CREATE PID=1234 PPID=5678 notepad.exe
ProcMon: EXIT   PID=1234
```

### Déchargement

```cmd
sc stop ProcMon
sc delete ProcMon
```

---

## protector — Protection de processus

### Compilation

Projet Driver (WDM) :
- Sources : `protector.c`
- **Important** : ajouter `/INTEGRITYCHECK` dans les options de l'éditeur de liens
  `ObRegisterCallbacks` nécessite aussi ce flag
- Résultat : `protector.sys`

Compiler séparément le client :
- Sources : `protector_ctl.c`
- Résultat : `protector_ctl.exe`

### Chargement

```cmd
sc create Protector type= kernel binPath= C:\path\to\protector.sys
sc start Protector
```

### Test

Lancer le processus à protéger (ex: notepad.exe). Récupérer son PID via le Gestionnaire des tâches.

```cmd
protector_ctl.exe 1234
```

Essayer de terminer le processus depuis le Gestionnaire des tâches ou avec taskkill :
```cmd
taskkill /PID 1234 /F
```
L'accès doit être refusé.

### Déchargement

```cmd
sc stop Protector
sc delete Protector
```

---

## unified — Driver combiné (bonus)

### Compilation

Projet Driver (WDM) :
- Sources : `unified.c`, `unified.h`
- Flag `/INTEGRITYCHECK` obligatoire
- Résultat : `unified.sys`

Client :
- Sources : `unified_ctl.c`, `unified.h`
- Résultat : `unified_ctl.exe`

### Utilisation

```cmd
sc create Unified type= kernel binPath= C:\path\to\unified.sys
sc start Unified

unified_ctl.exe protect 1234
unified_ctl.exe events
```

`events` affiche les 64 derniers événements de création/terminaison de processus stockés dans le ring buffer du driver.
