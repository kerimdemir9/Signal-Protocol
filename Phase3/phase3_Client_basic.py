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
import Phase1.Client as helper


API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

stuID = 0 # Enter your student ID
stuIDB = 18007



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
    global E
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = 1748178 #randint(0,n-2)
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



def IKRegReq(h,s,x,y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
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
    mes = {'ID': stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())



############## The new functions of phase 2 ###############

def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]


#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)
    print(response.json())
    if((response.ok) == True):
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)
    print(response.json())


############## The new functions of phase 3 ###############

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


############## The new functions of BONUS ###############

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, h, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'H': h, 'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, h, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'H': h, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
    print(response.json())


longTermPri = 104188328454886925485215855934907513813721063683343529163063087029381787393424

def checkAndHandleStatus():
    h, s = SignGen(stuID, E, longTermPri)
    status = Status(stuID, h, s)
    if(status.numOTK == 0):
        IK, SPK , OTKs = helper.registerUser()
        for i in range(10):
            print ("OTK", i, ":\n")
            # print(otks[i])
    else:
        print("getMessage")
        #mesajları al
    