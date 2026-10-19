# Rapport TP01 - Setup, WinDBG, BYOLD & Fuzzing

## Partie 1 - Mise en place

### Q1 : Subsystem d'un fichier .sys

Le subsystem d'un driver .sys est IMAGE_SUBSYSTEM_NATIVE (valeur 1). Contrairement aux executables classiques (.exe) qui ont un subsystem Windows GUI (2) ou Console (3), un driver n'est pas charge par le sous-systeme Win32 mais directement par le gestionnaire de pilotes du noyau. dumpbin /headers hello.sys montre la ligne "subsystem (0x1) native" dans le optional header.

### Q2 : sc start sans testsigning

Sans testsigning, Windows refuse de charger un driver non signe par un certificat reconnu. sc start retourne l'erreur 1275 (ERROR_DRIVER_BLOCKED) ou 577 (ERROR_INVALID_IMAGE_HASH). Windows verifie la signature Authenticode avant tout chargement de code kernel pour eviter qu'un attaquant charge un driver malveillant.

### Q3 : Etapes compilation -> DbgView

1. Ecriture de hello.c
2. Compilation avec msbuild en x64 Debug -> hello.sys genere
3. Copie du .sys dans la VM
4. sc create HelloDriver type= kernel binPath= C:\...\hello.sys
5. sc start HelloDriver
6. DbgView (Capture Kernel active) affiche "Hello: Driver loaded!"
7. sc stop -> "Hello: Driver unloaded"

## Partie 2 - WinDBG

### Q4 : Fonctions Ps*

x nt!Ps* retourne environ 150-200 fonctions selon la build Windows.

- PsLookupProcessByProcessId : retrouve le PEPROCESS a partir d'un PID. Elle incremente le compteur de reference, il faut appeler ObDereferenceObject ensuite.
- PsSetCreateProcessNotifyRoutineEx : enregistre une callback appelee a chaque creation/destruction de processus. Utilisee par les EDR pour monitorer l'activite.
- PsGetCurrentProcess : retourne le PEPROCESS du processus actuellement en cours d'execution sur le processeur, sans increment de reference.

### Q5 : Offsets _EPROCESS

Offsets releves avec dt nt!_EPROCESS sur Windows 10 21H2 x64 :

| Champ | Offset |
|---|---|
| UniqueProcessId | +0x440 |
| ActiveProcessLinks | +0x448 |
| Token | +0x4b8 |
| ImageFileName | +0x5a8 |

Ces valeurs changent selon la version de Windows, toujours verifier avec WinDBG.

### Q6 : Modification Flink/Blink

Si on modifie les pointeurs pour sauter un processus de la liste ActiveProcessLinks, ce processus disparait du Task Manager et de tasklist car ces outils parcourent cette liste pour enumerer les processus. Mais le processus continue de s'executer normalement car l'ordonnanceur (scheduler) utilise d'autres structures (_KPROCESS, files d'attente des threads) independantes de cette liste. C'est exactement la technique DKOM qu'on implementera au TP04.

### Q7 : Privileges System vs cmd.exe

Privileges presents dans System (PID 4) absents dans un cmd standard :
- SeTcbPrivilege
- SeCreateTokenPrivilege
- SeAssignPrimaryTokenPrivilege
- SeLoadDriverPrivilege

Si on copie le token de System dans le champ Token de cmd.exe, le cmd obtient immediatement les privileges SYSTEM. Tous ses appels systeme sont alors evalues avec ces privileges eleves. C'est la technique de token stealing du TP04.

## Partie 3 - BYOLD

### Q8 : Analyse PE de PROCEXP152.sys

| Champ | Valeur |
|---|---|
| Subsystem | Native (1) |
| Signe par | Microsoft Windows Hardware Compatibility Publisher |
| Taille | ~50 Ko environ |
| Sections | .text, .rdata, PAGE, INIT |

### Q9 : Signataire et revocation

Le signataire est Microsoft Windows Hardware Compatibility Publisher. Le certificat est valide. Microsoft ne peut pas simplement revoquer ce certificat car il signe des milliers d'autres drivers legitimes du programme WHCP. Bloquer uniquement PROCEXP152 par hash est possible (c'est ce qu'ils ont fait pour la v16.32 dans la blocklist) mais la v17 reste utilisable par des attaquants contre les processus non-PPL.

### Q10 : MajorFunction de PROCEXP152

Les fonctions enregistrees sont CREATE, CLOSE et surtout DEVICE_CONTROL (index 14). C'est via IRP_MJ_DEVICE_CONTROL que les IOCTLs sont dispatches depuis le userland. Le device s'appelle \Device\PROCEXP152, accessible via \\.\PROCEXP152.

### Q11 : Execution procexp_kill sur notepad

OpenProcess(PROCESS_TERMINATE) reussit car notepad n'est pas un processus protege. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) reussit aussi. L'IOCTL 0x8335003C renvoie un handle PROCESS_ALL_ACCESS. TerminateProcess avec ce handle tue notepad.

### Q12 : PROCESS_QUERY_LIMITED_INFORMATION non filtre

Ce droit a ete cree precisement pour que des outils de monitoring (Task Manager, antivirus) puissent interroger n'importe quel processus sans pouvoir le modifier. Microsoft a decide de ne pas le filtrer via ObRegisterCallbacks pour ne pas casser ces outils. Si on bloquait ce droit minimal, tasklist et le Task Manager ne pourraient plus lister les processus proteges, ce qui casserait le diagnostic systeme de base.

### Q12 bis : Fuzzing PROCEXP152

En fuzzant avec 500 iterations on trouve generalement 3 a 5 function codes qui repondent avec STATUS_SUCCESS, dont les codes correspondant a IOCTL_OPEN_PROTECTED_PROCESS_HANDLE (0x3C) et IOCTL_CLOSE_HANDLE. Les autres codes fonctionnels revelent probablement des fonctionnalites de listage de handles ou d'informations systeme utilisees par l'interface graphique de Process Explorer.

### Q13 : Analyse de la menace

1. PROCEXP152 est dangereux parce qu'il est signé Microsoft et fait exactement ce pour quoi il est concu. Un BYOVD comme RTCore64.sys exploite une faille memoire du driver, ce qui est plus detectables heuristiquement. Ici l'attaquant n'a pas besoin d'exploit, juste d'appeler une fonctionnalite documentee. Avantage principal : le driver passe tous les controles de signature.

2. La Microsoft Vulnerable Driver Blocklist bloque la v16.32 par hash mais pas la v17.02. Pour verifier si la blocklist est active : Get-CimInstance -ClassName Win32_DeviceGuard. Pour se proteger : WDAC avec des regles refusant explicitement le chargement de PROCEXP152 hors contexte legitime, plus HVCI pour renforcer l'integrite du code kernel.

3. Le driver protector.sys du TP03 enregistre ObRegisterCallbacks sur PsProcessType. Quand PROCEXP152 essaie d'obtenir un handle PROCESS_ALL_ACCESS sur un processus protege, il passe aussi par ObOpenObjectByPointer qui declenche ce meme callback. Donc en theorie protector.sys devrait bloquer PROCEXP152 aussi. A verifier experimentalement.

## Partie 4 - Fuzzer

### Q14 : Fuzzer sur HelloDriver

CreateFileW(\\\\.\\HelloDriver) echoue avec ERROR_FILE_NOT_FOUND (2) car HelloDriver ne cree aucun device (pas d'IoCreateDevice dans DriverEntry). Pas de lien symbolique dans le namespace, donc l'Object Manager ne trouve aucun objet correspondant.

### Q15 : Comparaison PROCEXP152 vs PhysicalDrive0

PROCEXP152 expose plus d'IOCTLs fonctionnels. PhysicalDrive0 est un device disque dont la plupart des IOCTL generiques (DeviceType=FILE_DEVICE_UNKNOWN) sont rejetes avant meme d'atteindre le code metier. PROCEXP152 en tant que "boite a outils" repond sur plusieurs function codes.

### Q16 : Breakpoints WinDBG

Pour 100 iterations du fuzzer, le breakpoint sur DispatchDeviceControl est atteint environ 100 fois (une fois par DeviceIoControl qui arrive jusqu'au driver). Quelques appels peuvent ne pas atteindre le breakpoint si le systeme rejette la requete avant (ex: parametres de securite de l'IRP invalides).
