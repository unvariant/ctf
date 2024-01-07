all:
	musl-gcc solve.c --static -o solve -mno-avx
	cp solve share/initramfs/home/user/jail/home/user
	cd share/initramfs ; find . | cpio -H newc -ov -F ../new.cpio
	mkdir -p share/initramfs/home/user/jail/home/user/share
	cp share/sina share/initramfs/home/user/jail/home/user/share/patch