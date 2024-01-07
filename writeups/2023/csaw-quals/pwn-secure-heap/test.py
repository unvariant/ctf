from Crypto.Cipher import ARC4

key = b'A' * 7
cipher = ARC4.new(key)
enc = cipher.encrypt(key)
print(enc)
cipher = ARC4.new(key)
enc = cipher.encrypt(enc)
print(enc)