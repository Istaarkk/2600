# Rapport TP02 - Driver Echo & MiniFilter

## Exercice 1 - Echo Driver

### Q1 : Pourquoi METHOD_BUFFERED

METHOD_BUFFERED est la methode la plus sure : l'I/O Manager copie lui-meme les buffers userland dans un buffer kernel intermediaire (SystemBuffer) avant que le driver y accede. Le driver ne touche jamais directement une adresse userland.

Les autres methodes et leurs risques :
- METHOD_IN_DIRECT / METHOD_OUT_DIRECT : le buffer de sortie est accede via une MDL mappee directement. Le driver doit valider lui-meme la taille et l'accessibilite, une erreur peut mener a un acces hors limites.
- METHOD_NEITHER : aucune validation par l'I/O Manager. Le driver recoit les pointeurs bruts du userland. Il faut appeler ProbeForRead/ProbeForWrite et gerer les TOCTOU manuellement. C'est la methode la plus dangereuse et la source classique de vulnerabilites dans les drivers tiers.

### Q2 : Oubli de IoCompleteRequest

Si on n'appelle pas IoCompleteRequest, l'IRP reste en attente indefiniment. Cote userland, DeviceIoControl ne retourne jamais : le thread reste bloque en attente de completion. Si beaucoup d'IRPs s'accumulent ainsi, ca peut epuiser les ressources, et au dechargement du driver on risque un BSOD car le systeme trouve des IRPs en vol dans un module qui se decharge.

### Q3 : Breakpoint WinDBG sur dispatch function

Apres sc start EchoDriver et avec un breakpoint sur EchoDriver!EchoDeviceControl :

```
kd> bp EchoDriver!EchoDeviceControl
kd> g
```

Quand user_echo.exe envoie le message, WinDBG s'arrete sur le breakpoint. On peut alors inspecter l'IRP avec dt _IRP et voir le SystemBuffer avec db. Le buffer contient la chaine envoyee depuis le userland.

## Exercice 2 - MiniFilter

### Q4 : Altitude d'un minifilter

L'altitude est un numero unique qui definit la position relative du filtre dans la pile de filtrage du Filter Manager. Plus le numero est eleve, plus le filtre est proche de l'application. Les EDR utilisent des altitudes entre 300000 et 400000 (plage FSFilter Activity Monitor) car cela les positionne au-dessus des filtres de chiffrement et compression, leur permettant d'intercepter les operations avant eux.

Si deux minifilters ont la meme altitude, le second echoue a l'enregistrement avec une erreur de collision d'altitude. L'altitude doit etre unique sur tout le systeme.

### Q5 : Nombre IRP_MJ_CREATE pour un fichier texte dans Notepad

En pratique on observe entre 5 et 15 operations IRP_MJ_CREATE pour l'ouverture d'un seul fichier. Ce nombre est superieur a 1 parce que :
- Notepad verifie d'abord les attributs du fichier avant de l'ouvrir vraiment
- Windows lit les flux alternatifs (Zone.Identifier pour les fichiers telecharges)
- L'antivirus present sur le systeme ouvre aussi le fichier pour l'analyser
- L'indexeur Windows Search peut declencher des ouvertures supplementaires
- La resolution du chemin implique parfois des ouvertures intermediaires

### Q6 (bonus) : Blocage des fichiers "secret"

Le minifilter bloque bien l'acces a C:\secret_data.txt. Pour le chemin court (8.3) : on utilise FLT_FILE_NAME_NORMALIZED qui resout les alias courts vers le nom long avant la comparaison. Le mot "secret" apparait toujours dans le nom normalise donc le blocage s'applique quand meme.
