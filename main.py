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
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random  # a bit better secure random number generation

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

stuID = 28853
curve = Curve.get_curve('secp256k1')
IKey_Ser_Pub = Point(int("1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9", 16),
                     int("ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff", 16), curve)
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

def IKRegVerify(ik_pri, ik_pub, code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(ik_pri)+"\n"+"IK.Pub.x: "+str(ik_pub[0])+"\n"+"IK.Pub.y: "+str(ik_pub[1]))
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


def concatenate(x, y):
    spk_x_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    spk_y_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
    concatenated_bytes = spk_x_bytes + spk_y_bytes
    return int.from_bytes(concatenated_bytes, byteorder='big')


# IK_Pub, IK_Pri = keyGen()
IK_Pub = ("0x669e867f04ccbc676470f44c6da945100f5ed97750ce35cab13461d0572261c2",
          "0xaf4ed418197b143264a8edb177e289dbe11b0c7335554683ba9844b14031a170")
IK_Pri = 1499533378629092443181884660138759147308836931401965846740365306604911800652
# h, s = sign_message(stuID, IK_Pri)
# IKRegReq(h, s, IK_Pub.x, IK_Pub.y)
verification_code = 630633
reset_code = 645077
reset_sig_stu_id_h, reset_sig_stu_id_s = sign_message(stuID, IK_Pri)
# IKRegVerify(IK_Pri, IK_Pub, verification_code)
SPK_Pub = (0x9907000b3b46c9308462dd70e0c0c2506cb562ff9ca25a916d2e67a68b5670e0 ,
           0xed4930f2f4f7cb77c84c62526158b4d820af068af899ee3242a697a69408721c)
SPK_Pri = 27280058814014322835872311304572730835600028459540571567859428260032877839542
# SPKReg(SPK_h, SPK_s, SPK_Pub.x, SPK_Pub.y)
T = SPK_Pri * IKey_Ser_Pub
U = (b'TheHMACKeyToSuccess' + T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
     + T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big'))

KHMAC = SHA3_256.new(U)
KHMAC = int(KHMAC.hexdigest(), 16)
KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length()+7)//8, byteorder='big')

OTKs = []
HMACs = []

for i in range(10):
    OTK_Pub, OTK_Pri = keyGen()

    OTK_Pub_x_to_byte = OTK_Pub.x.to_bytes((OTK_Pub.x.bit_length() + 7) // 8, byteorder='big')
    OTK_Pub_y_to_byte = OTK_Pub.y.to_bytes((OTK_Pub.y.bit_length() + 7) // 8, byteorder='big')

    hmac = HMAC.new(KHMAC_to_byte, OTK_Pub_x_to_byte + OTK_Pub_y_to_byte, digestmod=SHA256)
    hmac = hmac.hexdigest()
    HMACs.append(hmac)

    OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac)

