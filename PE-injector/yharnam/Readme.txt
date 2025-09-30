==================================================
         PROJET MALWARE - INJECTION DE CODE
==================================================
Matthieu Da Cruz
Thomas Fedorawiez
==================================================
MODALITÉS DE COMPILATION
==================================================

ÉTAPES DE COMPILATION:

1. nmake clean all sample

==================================================
COMPORTEMENTS DU MALWARE
==================================================

1. ANTI-DÉBOGAGE:
   - Détection via IsDebuggerPresent()
   - Arrêt immédiat si un débogueur est détecté
   - Message: "Debugger détecté arrêt du programme."

2. INFECTION DE RÉPERTOIRE:
   - Parcourt le répertoire courant ou spécifié
   - Recherche tous les fichiers .exe
   - Exclut son propre fichier (code.exe)
   - Pour chaque fichier trouvé:
     * Étend la dernière section PE
     * Injecte le payload
     * Modifie le point d'entrée
     * Rend la section exécutable

3. INFECTION DE PROCESSUS (BONUS):
   - Cible les processus en cours d'exécution
   - Processus ciblés: spécifié en paramètre (notepad.exe)
   - Fonctionnement:
     * Crée un snapshot des processus
     * Recherche le processus par nom
     * Alloue de la mémoire dans le processus cible
     * Copie et exécute le payload via CreateRemoteThread
   - Exemple d'utilisation:
     malware.exe . notepad.exe

4. PERSISTANCE:
   - Ajout dans la registry:
     HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
   - Clé: "Yharnam"
   - Valeur: chemin complet de l'exécutable

5. PAYLOAD:
   - Affiche une message box avec le texte "Hacked!"
   - Résolution dynamique des API via PEB
   - Utilise LoadLibraryA et GetProcAddress maison

==================================================
CARACTÉRISTIQUES TECHNIQUES
==================================================

FONCTIONS D'INJECTION:
- Modification des en-têtes PE
- Extension de section existante
- Préservation du point d'entrée original via delta
- Marquage IMAGE_SCN_MEM_EXECUTE

RÉSILIENCE:
- Détection de débogueur basique

==================================================
UTILISATION
==================================================

Syntaxe:
malware.exe [répertoire] [nom_processus]

Exemples:
malware.exe . notepad.exe       (Infecte le répertoire courant + notepad)
malware.exe C:\Target           (Infecte seulement le répertoire C:\Target)
malware.exe                     (Utilise le répertoire courant, pas d'infection process)

==================================================
PREUVE DE FONCTIONNEMENT
==================================================

Sortie console typique:
Injector!
Infecting: target.exe
Destruction
Infecting process: notepad.exe PID: 3248
Payload copied to remote process
Remote thread created successfully
Persistence added.

LIMITATIONS:
- Ne fonctionne qu'en 64 bits
- Payload basique (message box)