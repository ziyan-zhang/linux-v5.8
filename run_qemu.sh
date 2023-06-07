qemu-system-x86_64 \
	-nographic -serial mon:stdio -smp 2 -m 2048 \
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-hda ~/lab/ubuntu.img \
	-append "root=/dev/sda2 rw console=ttyS0" \
	-hdb ~/lab/ext4.img \
	-device nvme,drive=nvme1,serial=deadbeaf,num_queues=8 \
	-drive file=/home/zy/lab/disk.qcow,if=none,id=nvme1 -smp 4 \
