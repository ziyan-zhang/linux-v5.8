<!--
 * @Author: zy nscc ubuntu22.04 1920548152@qq.com
 * @Date: 2023-06-07 02:43:13
 * @LastEditors: zy nscc ubuntu22.04 1920548152@qq.com
 * @LastEditTime: 2023-06-07 15:26:24
 * @FilePath: /linux-v5.8/README
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
-->
# 详细教程和文件位置
调试文件系统详细版教程：
https://www.yuque.com/zhangziyan-blrbj/lhidou/ltogdk1p90efgkki

内核代码位置：`~/lab/linux-v5.8`

内核被编译到了：`~/lab/linux-v5.8/Linux_compiled`
# 制作根文件系统
发行版镜像位置~/lab/ubuntu.img，制作镜像（`--enable-kvm`简单启动能加，调试不能加，后面都不加了）：
```bash
qemu-img create -q -f qcow2 ubuntu.img 10G
sudo qemu-system-x86_64 -m 2048 -cdrom ubuntu-22.04.2-live-server-amd64.iso ubuntu.img
```
简单启动该镜像：
```bash
sudo qemu-system-x86_64 -m 2048 ubuntu.img
```
# 编译内核并启动
编译内核见文首教程。

指定内核启动该镜像：```~/lab/linux-v5.8/run_qemu.sh```
```bash
qemu-system-x86_64 \
	-nographic -serial mon:stdio -smp 2 -m 2048 \
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-hda ~/lab/ubuntu.img \
	-append "root=/dev/sda2 rw console=ttyS0" \
```

通过qemu调试：```~/lab/linux-v5.8/gdb_run_qemu.sh```，前面加```-s -S```：
```bash
qemu-system-x86_64 -s -S \
	-nographic -serial mon:stdio -smp 2 -m 2048 \
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-hda ~/lab/ubuntu.img \
	-append "root=/dev/sda2 rw console=ttyS0" \
```
# 加磁盘设备
下面以不调试为例，加设备。

## 1. 额外挂载scsi disk（格式化为ext4）：

制作ext4:
```bash
dd if=/dev/zero of=ext4.img bs=1M count=256
mkfs.ext4 ext4.img
```
qemu启动```run_qemu.sh```：
```bash
qemu-system-x86_64 \
	-nographic -serial mon:stdio -smp 2 -m 2048 \
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-hda ~/lab/ubuntu.img \
	-append "root=/dev/sda2 rw console=ttyS0" \
    -hdb ~/lab/ext4.img \
```
挂载sdb：
```bash
sudo mount /dev/sdb /mnt/scsimp/
```
看一下，
```bash
cat /proc/mounts
```
发现末行多了个新挂载的文件系统：
```plain
/dev/root / ext4 rw,relatime 0 0
...
/dev/sdb /mnt/scsimp ext4 rw,relatime 0 0
```
为了开机后不用每次挂载sdb，在```/etc/fstab/```里面加一行`：
```
/dev/sdb   /mnt/scsimp ext4    defaults    0   0
```
## 2. 额外挂载NVMe模拟磁盘
注意编译内核的时候设备选项里面，打开NVMe支持

### 制作模拟的NVMe磁盘
```bash
qemu-img create -f raw disk.qcow 1G
```
qemu启动：```run_qemu.sh```：
```bash
qemu-system-x86_64 \
	-nographic -serial mon:stdio -smp 2 -m 2048 \
	-kernel Linux_compiled/arch/x86_64/boot/bzImage \
	-hda ~/lab/ubuntu.img \
	-append "root=/dev/sda2 rw console=ttyS0" \
    -hdb ~/lab/ext4.img \
    -device nvme,drive=nvme1,serial=deadbeaf,num_queues=8 \
    -drive file=/home/zy/lab/disk.qcow,if=none,id=nvme1 -smp 4 \
```

### 对该NVMe磁盘分区
```bash
sudo fdisk /dev/nvme0n1
```
```plain
root@lab-nscc-qemu:~# fdisk /dev/nvme0n1

Welcome to fdisk (util-linux 2.37.2).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.

Device does not contain a recognized partition table.
Created a new DOS disklabel with disk identifier 0x3a8eb91f.

Command (m for help): n
Partition type
   p   primary (0 primary, 0 extended, 4 free)
   e   extended (container for logical partitions)
Select (default p): p
Partition number (1-4, default 1): 1
First sector (2048-2097151, default 2048): 
Last sector, +/-sectors or +/-size{K,M,G,T,P} (2048-2097151, default 2097151): 

Created a new partition 1 of type 'Linux' and of size 1023 MiB.

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
```
### 格式化磁盘一分区
列一下设备```ls /dev```，此时多出一个```/dev/nvme0n1p1```。格式化该分区，要先安装f2fs-tools，这时ubuntu发行版根文件系统的优势就体现出来了，直接apt上网下载。**注意要sodo，否则格式化分区不成功。**
```bash
sudo mkfs.f2fs -l nvmedisk /dev/nvme0n1p1
```
同上sdb，为了开机后不用每次挂载该NVMe盘，在```/etc/fstab/```里面加一行`：
```
/dev/nvme0n1p1	~/nvmemp	f2fs	defaults	0	0
```

Linux kernel
============

There are several guides for kernel developers and users. These guides can
be rendered in a number of formats, like HTML and PDF. Please read
Documentation/admin-guide/README.rst first.

In order to build the documentation, use ``make htmldocs`` or
``make pdfdocs``.  The formatted documentation can also be read online at:

    https://www.kernel.org/doc/html/latest/

There are various text files in the Documentation/ subdirectory,
several of them using the Restructured Text markup notation.

Please read the Documentation/process/changes.rst file, as it contains the
requirements for building and running the kernel, and information about
the problems which may result by upgrading your kernel.
