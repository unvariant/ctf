from pwn import u64

sc = open("sha256.dat", "rb").read()
sc = sc[:sc.index(b"AAAA")]
adjust = len(sc) + 63 & ~63;
sc = sc.ljust(adjust, b"\x90")
open("sha256.dat", "wb").write(sc)

qwords = [u64(sc[i:i+8]) for i in range(0, len(sc), 8)]
qwords = list(reversed(qwords))

with open("result.S", "w+") as f:
    f.write(f".intel_syntax noprefix\n.global _start\n_start:\n")
    f.write(f"mov rsp, 0x2000000 + 0xf00\n")
    f.write(f".rept 57\n.byte 0x90\n.endr\n")
    for qword in qwords:
        f.write(".byte 0x48, 0xb8\n")
        f.write(f".8byte {qword}\n")
        f.write(f"push rax\n")
        f.write(f".byte 0x90, 0x90, 0x90, 0x90, 0x90\n")
    adjust = 64 - 16 * len(qwords) % 64
    for i in range(adjust % 64):
        f.write(f".byte 0x90\n")
    f.write(f"mov rdi, rsp\n")
    f.write(f".rept 61\n.byte 0x90\n.endr\n")
    for ch in b"STOP":
        f.write(f".byte {ch}\n")