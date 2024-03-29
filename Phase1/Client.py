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
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random   # a bit better secure random number generation 

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

stuID = 28928

curve = Curve.get_curve('secp256k1')
x_hex = "1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9"
y_hex = "ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff"
x_decimal = int(x_hex, 16)
y_decimal = int(y_hex, 16)
IKey_Ser = Point(x_decimal, y_decimal, curve)

n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b


def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
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
    s_a = Random.new().read(int(math.log(n,2)))
    s_a = int.from_bytes(s_a, byteorder='big')%n
    q_a = s_a * P
    return s_a, q_a

def sign_message(private_key, message, curve):
    k = Random.new().read(int(math.log(curve.order, 2)))
    k = int.from_bytes(k, byteorder='big') % (curve.order - 1) + 1
    R = k * curve.generator
    r = R.x % curve.order
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    concatenated_bytes = r_bytes + message_bytes
    hasher = SHA3_256.new()
    hasher.update(concatenated_bytes)
    h = int.from_bytes(hasher.digest(), byteorder='big') % curve.order
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

def convert_and_concatenate(spk_x, spk_y):
    spk_x_bytes_length = (spk_x.bit_length() + 7) // 8
    spk_y_bytes_length = (spk_y.bit_length() + 7) // 8
    spk_x_bytes = spk_x.to_bytes(spk_x_bytes_length, byteorder='big')
    spk_y_bytes = spk_y.to_bytes(spk_y_bytes_length, byteorder='big')
    concatenated_bytes = spk_x_bytes + spk_y_bytes
    return int.from_bytes(concatenated_bytes, byteorder='big')

def gen_HMAC(spk_pri, iks_pub, curve):
    T = spk_pri * iks_pub
    predefined_str = b'TheHMACKeyToSuccess'
    T_y_bytes = T.y.to_bytes((T.y.bit_length() + 7) // 8, byteorder='big')
    T_x_bytes = T.x.to_bytes((T.x.bit_length() + 7) // 8, byteorder='big')
    U = predefined_str + T_y_bytes + T_x_bytes
    hasher = SHA3_256.new()
    hasher.update(U)
    KHMAC = hasher.digest()
    return KHMAC

def calculate_hmac_for_otk(otk_public, khmac):
    otk_x_bytes = otk_public.x.to_bytes((otk_public.x.bit_length() + 7) // 8, byteorder='big')
    otk_y_bytes = otk_public.y.to_bytes((otk_public.y.bit_length() + 7) // 8, byteorder='big')
    data = otk_x_bytes + otk_y_bytes
    hmac_obj = HMAC.new(khmac, digestmod=SHA256)
    hmac_obj.update(data)
    return hmac_obj.hexdigest()

def register_otks(curve, n, khmac, stuID):
    OTKs = []
    for i in range(10):
        otk_private, otk_public = keyGen()
        print ("OTK #", i, "private: ", otk_private)
        hmac_value = calculate_hmac_for_otk(otk_public, khmac)
        OTKReg(i, otk_public.x, otk_public.y, hmac_value)
        OTK = {"secret": otk_private, "public.x": otk_public.x, "public.y" : otk_public.y, "hmaci": hmac_value, "id": i}
        OTKs.append(OTK)
    return OTKs

def registerUser():
    s_a, q_a = keyGen()
    print("IK private:", s_a)
    h, s = sign_message(s_a, stuID, curve)

    IKRegReq(h, s, q_a.x, q_a.y)
    IK = {"secret": s_a, "public.x": q_a.x, "public.y": q_a.y, "h": h, "s": s}

    spkpr, spkpub = keyGen()
    print("SPK private: ", spkpr)
    
    spkpub_concatenated = convert_and_concatenate(spkpub.x, spkpub.y)
    h_pre, s_pre = sign_message(s_a, spkpub_concatenated, curve)

    SPKReg(h_pre, s_pre, spkpub.x, spkpub.y)
    SPK = {"secret": spkpr, "public.x": spkpub.x, "public.y":spkpub.y, "h": h_pre, "s": s_pre}
    khmac = gen_HMAC(spkpr, IKey_Ser, curve)

    OTKs = register_otks(curve, n, khmac, stuID)
    return IK, SPK, OTKs

def registerConferance():
    con_s_a, con_q_a = keyGen()
    h, s = sign_message(convert_and_concatenate(con_q_a.x, con_q_a.y), con_s_a, curve)
    #use exchange partial keys function in phase3