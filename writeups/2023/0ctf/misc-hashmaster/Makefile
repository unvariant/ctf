CC = gcc
ASM = nasm
CFLAGS = -no-pie -fPIC -fPIE -fno-asynchronous-unwind-tables


all: clean sha256

sha256:
	$(CC) sha256.c -o sha256.o -fno-stack-protector -masm=intel -nostdlib -fno-asynchronous-unwind-tables -fPIC -fPIE -c -O2 -funroll-all-loops -march=native -mtune=native -mavx512f;
	ld sha256.o --oformat=binary -T sha256.ld -o sha256.dat
	od -An -t x1 -v ./sha256.dat | sed 's/ /\\x/g' | tr -d \\n > sc.txt
	python3 conv.py
	as result.S -o result.o
	ld --oformat=binary -T result.ld -o result.dat result.o
	python3 strip.py
	cat result.dat sha256.dat > exp.dat

clean:
	rm -f sha256 sha256.o sha256.elf sc.txt