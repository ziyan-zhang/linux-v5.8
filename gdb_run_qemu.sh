qemu-system-x86_64 -s -S \
###
 # @Author: zy nscc ubuntu22.04 1920548152@qq.com
 # @Date: 2023-06-07 10:27:56
 # @LastEditors: zy nscc ubuntu22.04 1920548152@qq.com
 # @LastEditTime: 2023-06-07 13:36:03
 # @FilePath: /linux-v5.8/gdb_run_qemu.sh
 # @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
### 
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-drive file=/home/zy/lab/rootfs.ext2,if=ide,format=raw,id=myid0 \
	-append "root=/dev/sda console=ttyS0" -nographic \
	-hdb ~/lab/ext4.img \
	-device nvme,drive=nvme1,serial=deadbeaf,num_queues=8 \
	-drive file=/home/zy/lab/disk.qcow,if=none,id=nvme1 -smp 4
