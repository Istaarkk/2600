obj-m += rootkit.o
rootkit-objs := get_root.o hide.o hide_file.o hide_net.o persistence.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o companion companion.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f companion

deploy:
	sudo modprobe nbd max_part=8
	sudo qemu-nbd --connect=/dev/nbd0 disk.qcow2
	sleep 1
	sudo mount /dev/nbd0p1 /mnt
	sudo cp rootkit.ko /mnt/root/rootkit.ko
	sudo umount /mnt
	sudo qemu-nbd --disconnect /dev/nbd0

image:
	sudo ./build_image.sh disk.raw disk.qcow2

run:
	qemu-system-x86_64 -m 512M -drive file=disk.qcow2,format=qcow2 -nographic

run-debug:
	qemu-system-x86_64 -m 512M -drive file=disk.qcow2,format=qcow2 -nographic -s -S
