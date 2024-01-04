import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(0,n)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(0,n-2)
    R = k * P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (k - sA*h) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x%n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


stuID = 34701

#create a long term key
curve = Setup()
IKey_Pr = random.randint(1, curve.order)
P = curve.generator
IKey_Pub = IKey_Pr * P 
print("Identitiy Key is created")
print("IKey is a long term key and shouldn't be changed and private part should be kept secret. But this is a sample run, so here is my private IKey: ")
print(IKey_Pr)
IKey_Ser = Point(0x1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9 , 0xce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff, curve)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

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
    print(response.json())

############## The new functions of phase 2 ###############
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]

def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

################## Phase 1 Solution #####################

print("My ID number is",stuID)

print("Converted my ID to bytes in order to sign it:",stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'))
h, s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'), curve, IKey_Pr)

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Signature of my ID number is:\nh=",h,"\ns=",s)

print("+++++++++++++++++++++++++++++++++++++++++++++")


print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)

print("Received the verification code through email")

print("+++++++++++++++++++++++++++++++++++++++++++++")

code = int(input("Enter verification code which is sent to you: "))

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(code)

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Generating SPK...")
SPK_Pr, SPK_Pub = KeyGen(curve)
print("Private SPK: {}\nPublic SPK.x: {}\nPublic SPK.y: {}".format(SPK_Pr, SPK_Pub.x, SPK_Pub.y))
print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them")

toSign = SPK_Pub.x.to_bytes((SPK_Pub.x.bit_length()+7)//8, byteorder='big')+SPK_Pub.y.to_bytes((SPK_Pub.y.bit_length()+7)//8, byteorder='big')
print("Result will be like:", toSign)

print("+++++++++++++++++++++++++++++++++++++++++++++")

h, s = SignGen(toSign, curve, IKey_Pr)
print("Signature of SPK is:\nh=",h,"\ns=",s)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")

print("\n+++++++++++++++++++++++++++++++++++++++++++++")

SPKReg(h,s, SPK_Pub.x,SPK_Pub.y)


print("Creating HMAC key (Diffie Hellman)")

T = SPK_Pr*IKey_Ser
print("T is ", T)
U = b'TheHMACKeyToSuccess' + (T.y).to_bytes(((T.y).bit_length() + 7) // 8, byteorder='big') + (T.x).to_bytes(((T.x).bit_length() + 7) // 8, byteorder='big')
print("U is ", U)
K_hmac = SHA3_256.new(U).digest()
print("HMAC key is created ", K_hmac)
OTKs = {}
print("\n+++++++++++++++++++++++++++++++++++++++++++++")
print("Creating OTKs starting from index 0...")
for i in range(11):
    s, Q = KeyGen(curve)
    OTKs[i] = [s, Q.x, Q.y]
    print("{}th key generated. Private part={}\nPublic (x coordinate)={}\nPublic (y coordinate)={}".format(i,s, Q.x, Q.y))
    h = HMAC.new(K_hmac, digestmod=SHA256)
    print("x and y coordinates of the OTK converted to bytes and concatanated")
    message = Q.x.to_bytes((Q.x.bit_length()+7)//8, byteorder='big')+Q.y.to_bytes((Q.y.bit_length()+7)//8, byteorder='big')
    print("Message", message)
    h.update(message)
    hmac_ = h.hexdigest()
    print("HMAC is calculated and converted with 'hexdigest()': ")
    print(hmac_)
    isRegistered = OTKReg(i,Q.x,Q.y,hmac_)
    if(isRegistered): continue
    else: break

print("\nOTK keys were generated successfully!")


