import math
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random  # a bit better secure random number generation
import requests


API_URL = 'http://harpoon1.sabanciuniv.edu:9999'
stuID = 28853  # write your student ID
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

def IKRegVerify(IKey_Pr, IKey_Pub, code):
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

def keyGen():
    secret = Random.new().read(int(math.log(n, 2)))
    secret = int.from_bytes(secret, byteorder='big') % n
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


def concatenate(x, y):
    x_to_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    y_to_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
    return x_to_bytes + y_to_bytes


# IK_Pub, IK_Pri = keyGen() # generate IKs
IK_Pub = Point(99729665936069400189049630025268145612680094240728273595298801806858959619148,
               51191321905177615780693558879744615245596224651621976306951564536010637931746, curve)
IK_Pri = 68708997509867735893754012737457161590792631113345894906193292191370424524695

# sign IK_pri
h, s = sign_message(stuID, IK_Pri)
# Register my IK
# IKRegReq(h, s, IK_Pub.x, IK_Pub.y)

verification_code = 633909
reset_code = 518138
# ResetIK(reset_code)
# # reset signature
reset_sig_stu_id_h, reset_sig_stu_id_s = sign_message(stuID, IK_Pri)
# # Verify myself with the given code
# IKRegVerify(IK_Pri, IK_Pub, verification_code)

# SPK_Pub, SPK_Pri = keyGen()  # generate SPKs
SPK_Pub = Point(66331158853220778162825121078733586816456999454427083347515179674153920143331,
                45084201860451134626463936478291283412349276620097950808674494591713342720848, curve)
SPK_Pri = 51684599043567019427791939180673528490623665420756140617689541185560822669121

# sign SPKs and register
SPK_h, SPK_s = sign_message(int.from_bytes(concatenate(SPK_Pub.x, SPK_Pub.y), byteorder='big'), IK_Pri)
# SPKReg(SPK_h, SPK_s, SPK_Pub.x, SPK_Pub.y)

# Creating OTKs below part
T = SPK_Pri * IKey_Ser_Pub
U = b'TheHMACKeyToSuccess' + concatenate(T.y, T.x)

KHMAC = SHA3_256.new(U)
KHMAC = int(KHMAC.hexdigest(), 16)
KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length() + 7) // 8, byteorder='big')

OTKs = []
HMACs = []

ResetOTK(h, s)  # reset old OTKs

for i in range(10):
    OTK_Pub, OTK_Pri = keyGen()
    hmac = HMAC.new(KHMAC_to_byte, concatenate(OTK_Pub.x, OTK_Pub.y), digestmod=SHA256)
    hmac = hmac.hexdigest()
    OTKs.append((OTK_Pub, OTK_Pri))
    HMACs.append(hmac)

    OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac)
print("\n\n")
print("printing OTKs")
print("[")
for i in range(len(OTKs)):
    print("{")
    print("\"x\": {},".format(OTKs[i][0].x))
    print("\"y\": {},".format(OTKs[i][0].y))
    print("\"priv\": {},".format(OTKs[i][1]))
    print("\"hmac\": \"{}\"".format(HMACs[i]))
    print("},")
print("]")
