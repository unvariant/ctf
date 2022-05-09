# Internprise Encryption
This problem gives you a javascript file
```js
function encrypt(s) {
	let encrypted = [];
	for (let i = 0; i < s.length; i++) {
		let x = (s[i].charCodeAt(0x0) + i * 0xf) % 0x80;
		x += i > 0x0 ? encrypted[i - 0x1].charCodeAt(0) % 128 : 0xd;
		x ^= 0x555;
		x = ((x ^ ~0x0) >>> 0x0) & 0xff;
		x -= (Math.random() * 0x5) & 0xb9 & 0x46;
		x = ~(x ^ (0x2cd + ((i ^ 0x44) % 0x2 === 0) ? 0x3 : 0x0));
		x = ((x >> 0x1f) + x) ^ (x >> 0x1f);
		x |= ((Date.now() % 0x3e8) / (0x4d2 - 0xea)) | (i % 0x1);
		encrypted.push(String.fromCharCode(x));
	}
	return encrypted.join("");
}
```
and an encrypted flag.txt file. In order to decrypt the flag.txt file the encrypt function must be reverse engineered. It did not really take much, mostly just looking at the javascript and removing the useless parts to de-obfuscate it.
```python
# decrypt.py
f = open("flag.txt", 'r');

data = chr(13) + f.read();

for i in range(0, len(data)-1):
    cur = ((((~(~(-ord(data[i+1])) ^ 3)) ^ 0x555) % 256 - ord(data[i]) - i * 15) % 128);
    print(chr(cur), end='');

print()
```
Running the script produces the decrypted flag.txt
```
From: jared@business.biz
To: dave@business.biz
Subject: Fortune Telling Shenanigans
Content-Type: text/html
MIME-Version: 1.0

Hey Dave,
I went to a fortune teller the other day and while she divined my future, she mentioned you, strangely enough. 
I don't know why you came up if it was *my%#fortune that was being read, but she said something about "your coworker Dave"
and a "grave mistake," but I didn't read too much into it. She told me to send you this though: 
	sdctf{D0n't_b3_a_D4v3_ju5t_Use_AES_0r_S0me7h1ng}
I'm not sure why she wanted you to know this gibberish. I can't seem to make heads or tails of it.
Anyways are you coming to the company picnic this Saturday? I heard Carol from HR is bringing some of her world-famous 
deviled eggs.

Best, 
Jared from Accounting
```
## Flag: sdctf{D0n't_b3_a_D4v3_ju5t_Use_AES_0r_S0me7h1ng}