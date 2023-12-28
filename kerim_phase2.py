import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import phase2_Client_basic as helper


def concatenate(x, y):
    x_to_bytes = x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')
    y_to_bytes = y.to_bytes((y.bit_length() + 7) // 8, byteorder='big')
    return x_to_bytes + y_to_bytes


def generate_Ks(OTK_Priv_receiver, EK_Pub_sender, IK_Pub_sender, SPK_Pri_receiver, IK_Pri_receiver):
    T1 = IK_Pub_sender * SPK_Pri_receiver
    T2 = EK_Pub_sender * IK_Pri_receiver
    T3 = EK_Pub_sender * SPK_Pri_receiver
    T4 = EK_Pub_sender * OTK_Priv_receiver
    U = concatenate(T1.x, T1.y) + concatenate(T2.x, T2.y) + concatenate(T3.x, T3.y) + concatenate(T4.x,
                                                                                                  T4.y) + b'WhatsUpDoc'
    Ks = int(SHA3_256.new(U).hexdigest(), 16)
    return Ks


def KDF_Chain(kdf):
    k_enc = int(
        SHA3_256.new(kdf.to_bytes((kdf.bit_length() + 7) // 8, byteorder='big') + b'JustKeepSwimming').hexdigest(), 16)
    k_hmac = int(SHA3_256.new(concatenate(kdf, k_enc) + b'HakunaMatata').hexdigest(), 16)
    kdf_next = int(SHA3_256.new(concatenate(k_enc, k_hmac) + b'OhanaMeansFamily').hexdigest(), 16)
    return k_enc, k_hmac, kdf_next


curve = Curve.get_curve('secp256k1')
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b

IKey_Ser_Pub = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441,
                     93192522080143207888898588123297137412359674872998361245305696362578896786687, curve)

IK_Pub = Point(int("0x669e867f04ccbc676470f44c6da945100f5ed97750ce35cab13461d0572261c2", 16),
               int("0xaf4ed418197b143264a8edb177e289dbe11b0c7335554683ba9844b14031a170", 16), curve)
IK_Pri = 1499533378629092443181884660138759147308836931401965846740365306604911800652

SPK_Pub = Point(int("0x9907000b3b46c9308462dd70e0c0c2506cb562ff9ca25a916d2e67a68b5670e0", 16),
                int("0xed4930f2f4f7cb77c84c62526158b4d820af068af899ee3242a697a69408721c", 16), curve)
SPK_Pri = 27280058814014322835872311304572730835600028459540571567859428260032877839542

T = SPK_Pri * IKey_Ser_Pub
U = b'TheHMACKeyToSuccess' + concatenate(T.y, T.x)
KHMAC = SHA3_256.new(U)
KHMAC = int(KHMAC.hexdigest(), 16)
KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length() + 7) // 8, byteorder='big')

OTKs = [
    {
        "x": 2260961094018514118937523949554753558428811584984813038617243971974470517201,
        "y": 69962583839373983831432906219712649605272170246464586305517002125614834925720,
        "priv": 74148638507742914091642339533123309854283500905244899372498237839056304645314,
        "hmac": "ea006a35944b09d478ca32e2bf88b9041df96eece5c69dd3c8906b4b89bbec20"
    },
    {
        "x": 5510742376012695465495194748817866652627507720795039348252824371260330324658,
        "y": 8443807726448323357669706388859602834934855915592754600035209210133423153717,
        "priv": 77248405680011247651134638983444644520453354586519239073100095001573266105890,
        "hmac": "27083ab76670dbcc5a96b904f9c23aa372ce69148284145482db3aa04f97b0e9"
    },
    {
        "x": 5700853023586029269105769481819405498994414204563014262184281681925343604931,
        "y": 32433336904100328316892702918750067832425712963408444914843855742403663265796,
        "priv": 67921886148704889052044503241417026328365502839263901275357193149777906685629,
        "hmac": "b7f7c4bc6d63fa9b9a242e082f8a9599851f3aafc24341cee3993b90d1fdee5c"
    },
    {
        "x": 82727194109108326942491531827119226336683498799899657099565421122994166059884,
        "y": 100791220708529681378987342910085614642020042230374322399124353016411151738693,
        "priv": 83136871249336537549227149509137856488413838587491996231036740806744574668264,
        "hmac": "29ebf161133c51a7d9288789df7324845005d70754028b0343450c93c0590ae0"
    },
    {
        "x": 73835527263248907553839015724406789556654211609753415440573414469033873701954,
        "y": 92561861211021694717241171098603956621414755282417596256029380827045743497783,
        "priv": 101405429505260533942452260004736280197203454234173990850778805029400537773031,
        "hmac": "9377dd5403c6ad00eb4bedd9e716bcd900d50f6ae5a6088af4c6be19be71208b"
    },
    {
        "x": 42965286623271029276943756549787976623004943824576985124145709803760132041126,
        "y": 20689597745757527138486098559927056531431909876821226013644257407235482424607,
        "priv": 99945219818332447718819211945325583869598296760455388262003541822680312851745,
        "hmac": "ed69770a74cf77d468e9bc1bc577d54f812ad007efc51457b533b9225890cf0c"
    },
    {
        "x": 62033753934554316420460228527179475537352085844922073575936554917792553012865,
        "y": 91400217052013065862726142256103124094213464226170699367658807481728187818215,
        "priv": 9355175288794049043914137561764133869451492573053100339704123989703783137592,
        "hmac": "503c86ebeadd4174a9042f28e0a979d8ba56a467a073a10a7ebcc6b5e1947318"
    },
    {
        "x": 7023239996786756407623212856338637435828032403517746457219321496600144460260,
        "y": 34840237115111202735424626784931434954633121730292893902568676860968990497034,
        "priv": 21620775112750472734348830741689170561411851525381686383455502781660318964626,
        "hmac": "808cc1eda7514db00dc293f1b7990909bd0d9495ccd93e461b3104536b4e8576"
    },
    {
        "x": 89253331325608216190064139607288941928847802363683139199168919648057241811530,
        "y": 88276585449673234150886034393163878897708763862268743686882786424509549651728,
        "priv": 79498295097530786398155437715999972837729033216265738503902272140454323515267,
        "hmac": "215cdc3883765b9e840f1f2c2de5db637161f7a3afbe67e2bddbb0475a24b0e6"
    },
    {
        "x": 59299053449254539128999843941508868632801418235635911588167270461971278089096,
        "y": 66009793585067223538854792426143660547516846906924566801648618337078804907543,
        "priv": 71778284958819638601821663978160199327528708206157916033593191788846349593900,
        "hmac": "1c55cec444beefccb0591962759b4a8bc67ecf0398986cfefb71bfe23651ebcf"
    }
]
# this will make client send 5 messages to my inbox
h, s = helper.SignGen(helper.stuID, curve, IK_Pri)
helper.PseudoSendMsg(h, s)

messages = []

for i in range(5):
    sender_id, OTK_id, message_id, message, EK_x, EK_y = helper.ReqMsg(h, s)
    Ek = Point(EK_x, EK_y, curve)
    Ks = generate_Ks(OTKs[OTK_id]["priv"], Ek, IKey_Ser_Pub, SPK_Pri, IK_Pri)

    message_to_byte = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')

    for i in range(message_id):
        K_enc, K_HMAC, Ks = KDF_Chain(Ks)

    nonce = message_to_byte[:8]
    message = message_to_byte[8:-32]
    MAC = message_to_byte[-32:]

    aes = AES.new(K_enc, AES.MODE_CTR, nonce=nonce)

    plainText = aes.decrypt(message).decode()

    verify = HMAC.new(K_HMAC, digestmod=SHA256)
    found_mac = verify.update(message).digest()

    if found_mac == MAC:
        helper.Checker(helper.stuID, sender_id, message_id, plainText)
        messages.append(plainText)
    else:
        helper.Checker(helper.stuID, sender_id, message_id, "INVALIDHMAC")
