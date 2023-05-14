obj-m += netlink_virt_to_phys.o
KDIR := ~/sm8150/android_kernel_xiaomi_sm8150/out
all:
	make -C $(KDIR) M=$(PWD) ARCH=arm64 SUBARCH=arm64 modules
clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
