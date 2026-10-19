# TP01 - Setup, WinDBG, BYOLD & Fuzzing

## Contenu

- hello/hello.c - driver kernel minimal
- procexp_kill/procexp_kill.c - BYOLD via PROCEXP152
- fuzzer/ioctl_fuzzer.c - fuzzer d'IOCTL en C userland

## Compilation hello.sys

Necessite le WDK et un projet WDM (template fourni par l'enseignant ou cree via VS "Empty WDM Driver").

Via ligne de commande avec EWDK :
```
D:\LaunchBuildEnv.cmd
cd chemin\vers\hello
msbuild hello.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Compilation programmes userland

```
cl procexp_kill.c /Fe:procexp_kill.exe
cl ioctl_fuzzer.c /Fe:ioctl_fuzzer.exe
```

## Chargement dans la VM

```
bcdedit /set testsigning on
bcdedit /debug on
bcdedit /dbgsettings net hostip:<IP> port:50000 key:1.2.3.4
(reboot)

sc create HelloDriver type= kernel binPath= C:\...\hello.sys
sc start HelloDriver
sc stop HelloDriver
sc delete HelloDriver
```

## procexp_kill.exe

Necessite que PROCEXP152.sys soit charge (lancer procexp64.exe en admin au moins une fois).

```
procexp_kill.exe <PID>
```

## ioctl_fuzzer.exe

```
ioctl_fuzzer.exe \\.\HelloDriver 10
ioctl_fuzzer.exe \\.\PROCEXP152 500
```
