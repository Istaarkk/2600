# Rapport TP03 - Callbacks defensifs

## Exercice 1 - Process Monitor

### Q1 : Creation/destruction de notepad

Apres chargement de procmon.sys et lancement de notepad.exe, DbgView affiche :

```
ProcMon: [CREATE] PID=XXXX PPID=YYYY Image=\Device\HarddiskVolume3\Windows\System32\notepad.exe CmdLine=notepad.exe
ProcMon: [EXIT] PID=XXXX
```

Le PPID correspond a explorer.exe si notepad est lance depuis le bureau ou le menu Demarrer. Si lance depuis cmd.exe, le PPID est le PID du terminal.

### Q2 : Arbre de parente cmd -> whoami

Apres avoir lance cmd.exe puis execute whoami depuis ce terminal :

```
explorer.exe (PID A)
  -> cmd.exe (PID B, PPID=A)
       -> whoami.exe (PID C, PPID=B)
```

La callback capture correctement la chaine de creation. whoami.exe a pour PPID le PID du cmd qui l'a execute.

### Q3 : Fuzzer vu par le monitoring

Oui, le driver voit la creation du fuzzer. PsSetCreateProcessNotifyRoutineEx est appele pour toute creation de processus sans exception. On voit dans DbgView la creation de ioctl_fuzzer.exe avec son PID, le PID du cmd parent, le chemin complet de l'image et la ligne de commande complete incluant les arguments (ex: \\.\PROCEXP152 500). C'est tres utile pour un EDR car meme un outil offensif est visible avec tous ses arguments.

## Exercice 2 - Process Protector

### Q4 : Les 5 etapes de verification

1. notepad.exe lance, PID note
2. Driver charge avec ce PID dans PROTECTED_PID
3. taskkill /PID <pid> /F -> echoue avec "Acces refuse" : le driver a retire PROCESS_TERMINATE du masque avant que taskkill obtienne son handle
4. Fermeture via Task Manager -> echoue pour la meme raison
5. sc stop protector.sys -> ObUnRegisterCallbacks appele -> notepad redevient terminable

### Q5 : Contournement par un attaquant admin

Oui. La protection ObRegisterCallbacks intercepte les appels OpenProcess standards depuis le userland. Un attaquant admin peut :
- Charger PROCEXP152 (BYOLD du TP01) qui appelle ObOpenObjectByPointer depuis le kernel. Selon les tests, ce callback devrait aussi le filtrer mais c'est a verifier.
- Plus simplement, decharger directement le driver protector.sys avec sc stop (necessite les droits administrateur). La protection disparait instantanement.
- Utiliser un BYOVD qui ecrit directement en memoire kernel pour retirer le callback de la liste interne.

### Q6 : procmon + protector simultanes

procmon detecte la creation du processus taskkill.exe quand on essaie de tuer le processus protege. On voit [CREATE] taskkill.exe avec son PID et la ligne de commande. En revanche procmon ne logue pas directement l'echec de TerminateProcess, c'est le protector qui logue la tentative d'ouverture de handle avec PROCESS_TERMINATE dans ses propres DbgPrint. Les deux drivers sont complementaires.

## Exercice 3 (bonus) - Driver unifie

### Q7 : Vers un EDR minimal

Au moins 3 fonctionnalites a ajouter :

1. Monitoring des chargements de modules (DLL, drivers) via PsSetLoadImageNotifyRoutine. Indispensable pour detecter l'injection de code (process hollowing, DLL injection).

2. Monitoring des acces registre via CmRegisterCallbackEx pour intercepter les modifications de cles de persistance (Run, RunOnce, services) et bloquer les tentatives de desactivation des outils de securite.

3. Monitoring reseau via le framework WFP (FwpsCalloutRegister) pour observer les connexions sortantes et detecter les communications C2 ou l'exfiltration de donnees.
