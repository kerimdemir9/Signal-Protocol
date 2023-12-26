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


def generate_Ks(OTK_Priv, EK_Pub, IK_Pub_sender, SPK_Pri_receiver, IK_Pri_receiver):
    T1 = IK_Pub_sender * SPK_Pri_receiver
    T2 = EK_Pub * IK_Pri_receiver
    T3 = EK_Pub * SPK_Pri_receiver
    T4 = EK_Pub * OTK_Priv
    U = concatenate(T1.x, T1.y) + concatenate(T2.x, T2.y) + concatenate(T3.x, T3.y) + concatenate(T4.x, T4.y) + b'WhatsUpDoc'
    Ks = int(SHA3_256.new(U).hexdigest(), 16)
    return Ks


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
    {'ID': 28853, 'KEYID': 0, 'OTKI.X': 74725965994399624457922495519169815814674324160852099598674408668729843820932,
     'OTKI.Y': 31861574659548941275859281606136168877835538646740034228097093970680415491353,
     'HMACI': '0673ea141a91dcc824dc37a4d0f0204bae8e1f28e16e1fac131e2eb769e80571'},
    {'ID': 28853, 'KEYID': 1, 'OTKI.X': 5640487239760186090351899765169036673153643933708214727673278194974546567026,
     'OTKI.Y': 85680137853445792279376618901385739952972394189918488316319936106938206820273,
     'HMACI': '2c94d82bf78b3573eb5c248f80720538ecbbbc57153df1834840332736d2e43a'},
    {'ID': 28853, 'KEYID': 2, 'OTKI.X': 114836515266484115834024705887389020267925438198487708554019734766187012325754,
     'OTKI.Y': 26185836171285286214744076674457277455079180196394553047589753060231144052209,
     'HMACI': 'dcc6d4c55c3f499ef225b9dde861439a18d44c2f2bdbf00a7912828d6b0f66ef'},
    {'ID': 28853, 'KEYID': 3, 'OTKI.X': 76807951834185365351447112858375890133157982811581534905544625925112795517317,
     'OTKI.Y': 99355180397341320559914293433230754134467041157557973319713901474226865707105,
     'HMACI': '4d70a0d9ee28831c01401a3583ee9db6bde65dbdf1384eb180e4a7f427427049'},
    {'ID': 28853, 'KEYID': 4, 'OTKI.X': 76643692985821764191648918680981212416476519057470239206665777775382982822422,
     'OTKI.Y': 20984518853551697637023686886700417798344036460614896182314459987388875746496,
     'HMACI': 'ced815426bdb68c3e60cde92e835906268555724c0d90667f4c15ace15969755'},
    {'ID': 28853, 'KEYID': 5, 'OTKI.X': 19856674101903478261168890970439421011921166206643514670370594736169895247379,
     'OTKI.Y': 36845939471362371500219590789179030039951327776991833683045314123051589357272,
     'HMACI': '165da8039782149fb1332030bd5dbaaca6a79e5b06115805492fc6f8addc8171'},
    {'ID': 28853, 'KEYID': 6, 'OTKI.X': 73729197771312096261696668129354300014291603087150756248411547113080910890973,
     'OTKI.Y': 24454017904272610052880115683418605611354139920456414562533899422818695498586,
     'HMACI': '55ef999f0b3b456baab4d76d6f77157d57226ef853cdbcc0eb657d9d4cd639c9'},
    {'ID': 28853, 'KEYID': 7, 'OTKI.X': 23478261190126536815068073052007453217181217502391639423723866213570157725398,
     'OTKI.Y': 89143278099121999802898349817604808942802579683495840813614685978515690772500,
     'HMACI': 'e6016174347de4affa58b66628237b2ae8991ff9939f77d3629eeebbedbc7963'},
    {'ID': 28853, 'KEYID': 8, 'OTKI.X': 6578131778351140183190962487211731724210048380611877719755706477592770834485,
     'OTKI.Y': 94930433750227551766360460574419960270539143032149643939788753465180734570067,
     'HMACI': '9e7c68456d4084a179d6eef99d96fdf2ea374ff5d5c8caa97dafc57b284144ca'},
    {'ID': 28853, 'KEYID': 9, 'OTKI.X': 45108946533389577705005877750147041429611718225981285071489933329276807756032,
     'OTKI.Y': 3853217266068785219448547475421153930641424364359845554693617168224266196553,
     'HMACI': '5d05f456f63436db0d125cb1822e7ea10b57df1840b4d48726888e7d548e254e'}]

h, s = helper.SignGen(helper.stuID, curve, IK_Pri)
helper.PseudoSendMsg(h, s)  # this will make client send 5 messages to my inbox

for i in range(5):
    sender_id, OTK_id, message_id, message, EK_x, EK_y = helper.ReqMsg(h, s)
