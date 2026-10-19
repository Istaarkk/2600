# TP02 — Driver IOCTL et MiniFilter

## Prérequis

- Windows SDK + WDK installés (Visual Studio 2022 recommandé)
- VM avec testsigning activé :
  ```
  bcdedit /set testsigning on
  ```
- WinDBG configuré pour kernel debugging

---

## echo — Driver IOCTL

### Compilation

Créer un projet Driver (WDM) dans Visual Studio :
- Fichiers sources : `echo.c`, `echo.h`
- Configuration Release x64
- Résultat : `echo.sys`

Compiler le client userland séparément (projet console Win32) :
- Fichiers sources : `user_echo.c`, `echo.h`
- Résultat : `user_echo.exe`

### Chargement

```cmd
sc create EchoDriver type= kernel binPath= C:\path\to\echo.sys
sc start EchoDriver
```

### Test

```cmd
user_echo.exe "Hello kernel!"
```

Vérifier dans DebugView (ou WinDBG) : `Echo: Hello kernel!`

### Déchargement

```cmd
sc stop EchoDriver
sc delete EchoDriver
```

---

## filter — MiniFilter de logging

### Compilation

Créer un projet MiniFilter Driver dans Visual Studio :
- Fichiers sources : `filter.c`
- Résultat : `filter.sys`

### Installation

Copier `filter.reg` et l'importer :
```cmd
reg import filter.reg
```

Ou créer manuellement la clé :
```
HKLM\SYSTEM\CurrentControlSet\Services\FileFilter
  Type = 1
  Start = 3
  ImagePath = \??\C:\path\to\filter.sys
  Altitude = 370000
  Flags = 0
```

### Chargement

```cmd
fltmc load FileFilter
fltmc instances
```

### Test

Ouvrir n'importe quel fichier — les accès apparaissent dans DebugView :
```
Filter: IRP_MJ_CREATE C:\Windows\System32\notepad.exe
```

Bonus : tenter d'ouvrir un fichier contenant "secret" dans son nom — le driver retourne `STATUS_ACCESS_DENIED`.

### Déchargement

```cmd
fltmc unload FileFilter
```
