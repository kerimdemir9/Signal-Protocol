import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
import requests
import random
import re
import json
import Crypto
from Crypto.Hash import SHA3_256
from Crypto import Random  # a bit better secure random number generation

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

stuID = 28853
IK_Ser_Pub = {
    "x": "1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9",
    "y": "ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff",
    "x_dec": int("1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9", 16),
    "y_dec": int("ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff", 16)
}
curve = Curve.get_curve('secp256k1')
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
    print(response.json())

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


def concatenate_integers(num1, num2):
    concatenated_str = str(num1) + str(num2)
    return int(concatenated_str)


def keyGen():
    secret = Random.new().read(int(math.log(n, 2)))
    secret = int.from_bytes(secret, byteorder='big') % n
    print("My secret", secret)
    public = secret * P
    return public, secret


def sign_message(message, private_key):
    k = Random.new().read(int(math.log(curve.order, 2)))
    k = int.from_bytes(k, byteorder='big') % (curve.order - 1) + 1

    R = k * P
    r = R.x % n

    r_to_byte = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    message_to_byte = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')

    hasher = SHA3_256.new().update(r_to_byte + message_to_byte)
    h = int.from_bytes(hasher.digest(), byteorder='big') % n
    s = (k - private_key * h) % curve.order

    return (h, s)


def verify_signature(public_key, message, signature, curve):
    h, s = signature

    V = s * curve.generator + h * public_key
    v = V.x % curve.order

    v_bytes = v.to_bytes((v.bit_length() + 7) // 8, byteorder='big')
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')

    concatenated_bytes = v_bytes + message_bytes

    hasher = SHA3_256.new()
    hasher.update(concatenated_bytes)
    h_prime = int.from_bytes(hasher.digest(), byteorder='big') % curve.order

    return h == h_prime


def concatenate_integers_as_bytes(num1, num2):
    num1_bytes_length = (num1.bit_length() + 7) // 8
    num2_bytes_length = (num2.bit_length() + 7) // 8

    num1_bytes = num1.to_bytes(num1_bytes_length, byteorder='big')
    num2_bytes = num2.to_bytes(num2_bytes_length, byteorder='big')

    concatenated_bytes = num1_bytes + num2_bytes

    return int.from_bytes(concatenated_bytes, byteorder='big')


# IK_Pub, IK_Pri = keyGen()
IK_Pub = ("0x669e867f04ccbc676470f44c6da945100f5ed97750ce35cab13461d0572261c2",
          "0xaf4ed418197b143264a8edb177e289dbe11b0c7335554683ba9844b14031a170")
IK_Pri = 1499533378629092443181884660138759147308836931401965846740365306604911800652
# h, s = sign_message(stuID, IK_Pri)
# IKRegReq(h, s, IK_Pub.x, IK_Pub.y)
verification_code = 630633
reset_code = 645077
# IKRegVerify(IK_Pri, IK_Pub, verification_code)
SPK_Pub = 0
SPK_Pri = 0