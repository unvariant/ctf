flag = "";
shuf = "_ynourtsd_tet_eh2_bfiasl7cedbda7";
for i in range(4):
    flag += shuf[i * 8 + 5];
    flag += shuf[i * 8 + 4];
    flag += shuf[i * 8 + 7];
    flag += shuf[i * 8 + 6];
    flag += shuf[i * 8 + 1];
    flag += shuf[i * 8];
    flag += shuf[i * 8 + 3];
    flag += shuf[i * 8 + 2];

print(flag);