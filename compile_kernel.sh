make ARCH=x86_64 defconfig O=./Linux_compiled
cd ./Linux_compiled
make ARCH=x86_64 menuconfig
make ARCH=x86_64 -j $(nproc)
