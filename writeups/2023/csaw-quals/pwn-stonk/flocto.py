import grequests
import json

ADDRESS = "http://stonk.csaw.io"
PORT = 4657

key = "FLOCTOB"

def subdomain(path):
    return ADDRESS + ":" + str(PORT) + path

r = grequests.post(subdomain("/login"), data={"key":key})
r = grequests.map([r])[0]
print(r.text)

reqs = []
for _ in range(2):
    reqs.append(grequests.post(subdomain("/buy"), data={"key":key, "stock":"AAPLISH"})) # fill up requests

# reqs.append(grequests.post(subdomain("/trade"), data={"key":key, "stock":"AAPLISH", "stock1":"FACEFLOP"}))

r = grequests.map(reqs)
for i in range(len(r)):
    print(r[i].text)

r = grequests.post(subdomain("/login"), data={"key":key})
r = grequests.map([r])[0]
print(r.text)