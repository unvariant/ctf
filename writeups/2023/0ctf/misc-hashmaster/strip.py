sc = open("result.dat", "rb").read()
sc = sc[:sc.index(b"STOP")]
open("result.dat", "wb").write(sc)