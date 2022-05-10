# Bit Flipping Machine (Part 1)
I am not sure if I was doing something wrong, but the decompiled `ghidra` output for the cpp file was not only unreadable but misleading.
```cpp
void run_challenge(basic_string param_1,basic_string param_2)

{
  char cVar1;
  char cVar2;
  byte bVar3;
  bool bVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  basic_ostream *pbVar8;
  ulong uVar9;
  char *pcVar10;
  byte *pbVar11;
  undefined4 in_register_00000034;
  undefined4 in_register_0000003c;
  basic_string *pbVar12;
  long in_FS_OFFSET;
  basic_string local_48 [10];
  long local_20;
  
  pbVar12 = (basic_string *)CONCAT44(in_register_0000003c,param_1);
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  pbVar8 = std::operator<<((basic_ostream *)std::cout,"Change \"");
  pbVar8 = std::operator<<(pbVar8,pbVar12);
  pbVar8 = std::operator<<(pbVar8,"\" to \"");
  pbVar8 = std::operator<<(pbVar8,(basic_string *)CONCAT44(in_register_00000034,param_2));
  pbVar8 = std::operator<<(pbVar8,"\":");
  pbVar8 = (basic_ostream *)
           std::basic_ostream<char,std::char_traits<char>>::operator<<
                     ((basic_ostream<char,std::char_traits<char>> *)pbVar8,
                      std::endl<char,std::char_traits<char>>);
  std::operator<<(pbVar8,"Enter the secret flip codes for this machine: ");
  std::basic_ostream<char,std::char_traits<char>>::flush();
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
                    /* try { // try from 00102526 to 001026ea has its CatchHandler @ 00102709 */
  std::getline<char,std::char_traits<char>,std::allocator<char>>((basic_istream *)std::cin,local_48)
  ;
  uVar5 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
  if (((uVar5 & 3) == 0) &&
     (uVar9 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length()
     , uVar9 < 0x401)) {
    bVar4 = false;
  }
  else {
    bVar4 = true;
  }
  if (bVar4) {
    badcode();
  }
  while (pcVar10 = (char *)std::__cxx11::
                           basic_string<char,std::char_traits<char>,std::allocator<char>>::
                           operator[]((ulong)local_48), *pcVar10 != '\0') {
    pcVar10 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                      operator[]((ulong)local_48);
    cVar1 = *pcVar10;
    pcVar10 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                      operator[]((ulong)local_48);
    cVar2 = *pcVar10;
    iVar6 = isupper((int)cVar1);
    if ((iVar6 == 0) || (iVar6 = isupper((int)cVar2), iVar6 == 0)) {
      badcode();
    }
    iVar7 = (cVar1 + -0x41) * 0x1a + cVar2 + -0x41;
    iVar6 = iVar7;
    if (iVar7 < 0) {
      iVar6 = iVar7 + 7;
    }
    uVar9 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length();
    if (uVar9 <= (ulong)(long)(iVar6 >> 3)) {
      badcode();
    }
    pbVar11 = (byte *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                      operator[]((ulong)pbVar12);
    bVar3 = (byte)(iVar7 >> 0x37);
    *pbVar11 = (byte)(0x80 >> (((char)iVar7 + (bVar3 >> 5) & 7) - (bVar3 >> 5) & 0x1f)) ^ *pbVar11;
  }
  bVar4 = std::operator!=(pbVar12,(basic_string *)CONCAT44(in_register_00000034,param_2));
  if (bVar4 == false) {
    pbVar8 = std::operator<<((basic_ostream *)std::cout,
                             "Good job. You flipped this one correctly.\n");
    std::basic_ostream<char,std::char_traits<char>>::operator<<
              ((basic_ostream<char,std::char_traits<char>> *)pbVar8,
               std::endl<char,std::char_traits<char>>);
    std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
              ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_48);
    if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
      return;
    }
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  pbVar8 = std::operator<<((basic_ostream *)std::cout,
                           "Oh noes. The string isn\'t flipped correctly.");
  std::basic_ostream<char,std::char_traits<char>>::operator<<
            ((basic_ostream<char,std::char_traits<char>> *)pbVar8,
             std::endl<char,std::char_traits<char>>);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
Trying to read this hurt my eyes so I gave up and just wrote my own disassembly by objdumping the binary and parsing the assembly.
```c
// p0 = "rm -rf /trash/"
// p1 = "rm -rf ///////"

run_chall(p0, p1):
    input = read(stdin);

    if (input.len() % 4 != 0) || (input.len() > 1024) {
        invalid();
    }   

    counter = 0;
    while input[counter] != 0 { 
        ch0 = input[counter];
        ch1 = input[counter+1];
            
        if !ch0.isupper() || !ch1.isupper() {
            invalid();
        }   

        var0 = (ch0 - 65) * 26 + ch1 - 65; 
        var1 = var0 / 8;

        if (unsigned)var1 >= p0.len() {
            invalid();
        }

        ch = p0[var1];
        shift = var0 % 8;
        p0[var1] = (0b10000000 >> shift) ^ ch; 
        counter += 2;
    }   

    if p0 == p1 {
        println!("you got the flag!");
    } else {
        println!("try again");
    }   
}
```
This was much cleaner (I cut out some unnecessary code) and easier to understand, and I wrote a simple script to generate the proper input.
```rust
fn main() {
    let target: Vec<char> = String::from("rm -rf ///////").chars().collect();
    let mut change: Vec<char> = String::from("rm -rf /trash/").chars().collect();
    let mut ret = String::new();

    for i in 0..(change.len()) {
        for s in (0..8).rev() {
            let n = change[i] as u8;
            if (n >> s) & 1 != (target[i] as u8 >> s) & 1 {
                let t = i as u8 * 8 + 7 - s;
                let ch0 = t / 26;
                let ch1 = t - ch0 * 26;
                ret.push((65 + ch0) as char);
                ret.push((65 + ch1) as char);
            }
        }
    }

    let mut chars: Vec<char> = ret.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let ch0 = chars[i];
        let ch1 = chars[i+1];

        let n = (ch0 as u8 - 65) * 26 + ch1 as u8 - 65;
        let idx = (n / 8) as usize;
        let ch = change[idx] as u8;
        change[idx] = (ch ^ (0b10000000 >> (n % 8))) as char;
    }

    println!("{:?}", change);
    println!("{}", ret);
    println!("{}", ret.len());
}
```
It spat a string of characters: `CNCPCQCSCTCVCXCYCZDBDDDGDHDIDLDNDODPDTDXDYDZ`
```
== proof-of-work: disabled ==
Welcome to Bit Flipper. Flip the right bits to change one string to another
*** Let's start with a warmup ***
Change "rm -rf /trash/" to "rm -rf ///////":
Enter the secret flip codes for this machine: CNCPCQCSCTCVCXCYCZDBDDDGDHDIDLDNDODPDTDXDYDZ
Good job. You flipped this one correctly.

Good job! Here is an intermediate flag:
sdctf{s3Cr3T_C0d3_15_RaDIx26_b1t_p0SIti0n5}
```
## Flag: sdctf{s3Cr3T_C0d3_15_RaDIx26_b1t_p0SIti0n5}
(I unfortunately did not have enough time to do part 2 as I finished the solution for part 1 just before the competition ended)

# Bit Flipping Machine Part 2
(After the competition ended)
I ran the script above on the second input
```
*** To get the final flag, complete this harder one. ***
Change "Send Mallory 1000 USD" to "Send Mallory 9999 BTC":
Enter the secret flip codes for this machine: EEEMEPEUEXFCFFFRFTFUFVGBGCGDGJGKGL
Invalid code
```
The issue was that the input string length was not a multiple of 4, and I thought there was no way to pad it out to be a multiple of 4 bytes because the only possible sequence to add would be two identical character sequences to flip and then unflip a bit, which would not pad it out to a multiple of 4.<br>
After reading other writeups on this problem, the solution was actually to add two null bytes to the end of the string. This is because cpp's string length does not rely on null terminators, instead on an internal length field. So by padding the input with two null bytes the length check would be passed and the loop would never process the null bytes as it stops as soon as it finds a null byte (I would never have solved part 2 I had no idea cpp worked this way).