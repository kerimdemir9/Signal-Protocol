import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
import requests
import random
import re
import json
import Crypto
from Crypto.Hash import SHA3_256

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

stuID = 28928

curve = Curve.get_curve('secp256k1')
x_hex = "1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9"
y_hex = "ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff"
x_decimal = int(x_hex, 16)
y_decimal = int(y_hex, 16)
ikpub = Point(x_decimal, y_decimal, curve)

n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b


def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)		
    if((response.ok) == False): 
        print(response.json())
    else: 
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())

def concatenate_numbers(num1, num2):
    concatenated_str = str(num1) + str(num2)
    return int(concatenated_str)

def keyGen():
    s_a = random.randint(1, n - 1)
    q_a = s_a * P
    return s_a, q_a

def sign_message(m, s_a):
    k = random.randint(0, n - 1)
    R = k * P
    r = R.x
    concatenated = concatenate_numbers(r, m)
    hasher = SHA3_256.new()  # Create a new SHA3_256 object
    hasher.update(concatenated.to_bytes((concatenated.bit_length() + 7) // 8, byteorder='big'))  # Update the hasher with the concatenated data
    h = int.from_bytes(hasher.digest(), byteorder='big') % n
    s = (k - h * s_a) % n
    return h, s

def verify_signature(m, s, h, q_a):
    V = s * P + h * q_a
    v = V.x
    h_prime = SHA3_256(concatenate_numbers(v, m)) % n
    return h == h_prime
s_a, q_a = keyGen()
h, s = sign_message(stuID, s_a)
messageToSend = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': ikpub.x, 'IKPUB.Y': ikpub.y}