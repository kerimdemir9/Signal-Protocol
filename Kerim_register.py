import math
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random  # a bit better secure random number generation
import helper

stuID = 28853
curve = Curve.get_curve('secp256k1')
IKey_Ser_Pub = Point(int("1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9", 16),
                     int("ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff", 16), curve)
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b


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
IK_Pub = Point(int("0x669e867f04ccbc676470f44c6da945100f5ed97750ce35cab13461d0572261c2", 16),
               int("0xaf4ed418197b143264a8edb177e289dbe11b0c7335554683ba9844b14031a170", 16), curve)
IK_Pri = 1499533378629092443181884660138759147308836931401965846740365306604911800652

# sign IK_pri
h, s = sign_message(stuID, IK_Pri)
# Register my IK
helper.IKRegReq(h, s, IK_Pub.x, IK_Pub.y)

verification_code = 630633
reset_code = 645077
# reset signature
reset_sig_stu_id_h, reset_sig_stu_id_s = sign_message(stuID, IK_Pri)
# Verify myself with the given code
helper.IKRegVerify(IK_Pri, IK_Pub, verification_code)

# SPK_Pub, SPK_Pri = keyGen() # generate SPKs
SPK_Pub = Point(int("0x9907000b3b46c9308462dd70e0c0c2506cb562ff9ca25a916d2e67a68b5670e0", 16),
                int("0xed4930f2f4f7cb77c84c62526158b4d820af068af899ee3242a697a69408721c", 16), curve)
SPK_Pri = 27280058814014322835872311304572730835600028459540571567859428260032877839542

# sign SPKs
SPK_h, SPK_s = sign_message(int.from_bytes(concatenate(SPK_Pub.x, SPK_Pub.y), byteorder='big'), IK_Pri)
helper.SPKReg(SPK_h, SPK_s, SPK_Pub.x, SPK_Pub.y)

# Creating OTKs below part
T = SPK_Pri * IKey_Ser_Pub
U = b'TheHMACKeyToSuccess' + concatenate(T.y, T.x)

KHMAC = SHA3_256.new(U)
KHMAC = int(KHMAC.hexdigest(), 16)
KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length() + 7) // 8, byteorder='big')

OTKs = []
HMACs = []

for i in range(10)
    OTK_Pub, OTK_Pri = keyGen()
    hmac = HMAC.new(KHMAC_to_byte, concatenate(OTK_Pub.x, OTK_Pub.y), digestmod=SHA256)
    hmac = hmac.hexdigest()
    OTKs.append((OTK_Pub, OTK_Pri))
    HMACs.append(hmac)

    helper.OTKReg(i, OTK_Pub.x, OTK_Pub.y, hmac)
