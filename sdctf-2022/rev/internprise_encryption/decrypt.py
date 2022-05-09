f = open("flag.txt", 'r');

data = chr(13) + f.read();

for i in range(0, len(data)-1):
    cur = ((((~(~(-ord(data[i+1])) ^ 3)) ^ 0x555) % 256 - ord(data[i]) - i * 15) % 128);
    print(chr(cur), end='');

print()