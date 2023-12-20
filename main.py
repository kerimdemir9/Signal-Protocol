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


stuID = 28853

curve = Curve.get_curve('secp256k1')
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b


def keyGen():
    IK_secret = random.new().read(int(math.log(n, 2)))
    IK_secret = int.from_bytes(IK_secret, byteorder='big') % n
    IK_public = IK_secret * P

    return IK_public, IK_secret

def sigGen(IK_public)
