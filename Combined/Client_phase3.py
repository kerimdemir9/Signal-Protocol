import math
import json
from Crypto.Cipher import AES
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random
import secrets
import requests


def readJson(file_name):
    with open(file_name, 'r') as file:
        OTK = json.load(file)
    return OTK


def updateJson(file_name, data):
    with open(file_name, 'w') as file:
        json.dump(data, file, indent=4)


API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

stuID_A = 28853
stuID_B = 18007
curve = Curve.get_curve('secp256k1')
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b

messages = []

IKey_Ser_Pub = Point(int("1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9", 16),
                     int("ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff", 16), curve)


def IKRegReq(h, s, x, y):
    mes = {'ID': stuID_A, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False): print(response.json())


def IKRegVerify(code):
    mes = {'ID': stuID_A, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    print(response.json())


def SPKReg(h, s, x, y):
    mes = {'ID': stuID_A, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    print(response.json())


def OTKReg(keyID, x, y, hmac):
    mes = {'ID': stuID_A, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetIK(rcode):
    mes = {'ID': stuID_A, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetSPK(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetOTK(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())


def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s * P + h * QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length() + 7) // 8, byteorder='big') + message).digest(),
                        byteorder='big') % n
    if h_ == h:
        return True
    else:
        return False


############## The new functions of phase 2 ###############

def PseudoSendMsg(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json=mes)
    print(response.json())


# Get your messages. server will send 1 message from your inbox
def ReqMsg(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]


# Get the list of the deleted messages' ids.
def ReqDelMsg(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["MSGID"]


# If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())


############## The new functions of phase 3 ###############

# Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h, s):
    mes = {'ID': stuID_A, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())


# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky,
           "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB': stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json())
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res[
            'OTK.X'], res['OTK.Y']

    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


# Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

    # ---------------------------------------- CUSTOM METHODS ------------------------------------------


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


def generate_Ks_receiver(OTK_Priv_receiver, EK_Pub_sender, IK_Pub_sender, SPK_Pri_receiver, IK_Pri_receiver):
    T1 = IK_Pub_sender * SPK_Pri_receiver
    T2 = EK_Pub_sender * IK_Pri_receiver
    T3 = EK_Pub_sender * SPK_Pri_receiver
    T4 = EK_Pub_sender * OTK_Priv_receiver
    U = concatenate(T1.x, T1.y) + concatenate(T2.x, T2.y) + concatenate(T3.x, T3.y) + concatenate(T4.x,
                                                                                                  T4.y) + b'WhatsUpDoc'
    Ks = int(SHA3_256.new(U).hexdigest(), 16)
    return Ks


def generate_Ks_sender(IK_Pub_b, Ek_Pri_sender, SPK_Pub_b, IK_Pri_sender, OTK_Pub_b):
    T1 = SPK_Pub_b * IK_Pri_sender
    T2 = IK_Pub_b * Ek_Pri_sender
    T3 = SPK_Pub_b * Ek_Pri_sender
    T4 = OTK_Pub_b * Ek_Pri_sender
    U = concatenate(T1.x, T1.y) + concatenate(T2.x, T2.y) + concatenate(T3.x, T3.y) + concatenate(T4.x,
                                                                                                  T4.y) + b'WhatsUpDoc'

    return int(SHA3_256.new(U).hexdigest(), 16)  # Ks is the return value


def KDF_Chain(kdf):
    k_enc = int(
        SHA3_256.new(kdf.to_bytes((kdf.bit_length() + 7) // 8, byteorder='big') + b'JustKeepSwimming').hexdigest(), 16)
    k_hmac = int(SHA3_256.new(concatenate(kdf, k_enc) + b'HakunaMatata').hexdigest(), 16)
    kdf_next = int(SHA3_256.new(concatenate(k_enc, k_hmac) + b'OhanaMeansFamily').hexdigest(), 16)
    return k_enc, k_hmac, kdf_next


def keyGen():
    secret = Random.new().read(int(math.log(n, 2)))
    secret = int.from_bytes(secret, byteorder='big') % n
    public = secret * P
    return public, secret


def registerIK():
    updateJson("./OTK.json", [])
    updateJson("./Keys.json", {
        "IK_Pub_x": 0,
        "IK_Pub_y": 0,
        "IK_Pri": 0,
        "SPK_Pub_x": 0,
        "SPK_Pub_y": 0,
        "SPK_Pri": 0
    })
    data = readJson("./Keys.json")
    public_key, private_key = keyGen()
    h, s = sign_message(stuID_A, private_key)
    IKRegReq(h, s, public_key.x, public_key.y)

    data["IK_Pub_x"] = public_key.x
    data["IK_Pub_y"] = public_key.y
    data["IK_Pri"] = private_key

    updateJson("./Keys.json", data)


def verifyIKAndRegisterSPKAndOTKs(verificationCode):
    keys = readJson("./Keys.json")
    IKRegVerify(verificationCode)
    spk_pub, spk_priv = keyGen()
    spk_h, spk_s = sign_message(int.from_bytes(concatenate(spk_pub.x, spk_pub.y), byteorder='big'), keys["IK_Pri"])
    SPKReg(spk_h, spk_s, spk_pub.x, spk_pub.y)

    keys["SPK_Pub_x"] = spk_pub.x
    keys["SPK_Pub_y"] = spk_pub.y
    keys["SPK_Pri"] = spk_priv

    updateJson("./Keys.json", keys)

    for i in range(10):
        generateOTK(i)


def encrypt(k_hmac, k_enc, message):
    k_enc_byte = k_enc.to_bytes((k_enc.bit_length() + 7) // 8, byteorder='big')
    k_hmac_byte = k_hmac.to_bytes((k_hmac.bit_length() + 7) // 8, byteorder='big')

    # random 8 byte nonce
    nonce = secrets.token_bytes(8)
    # encryption algorithm
    aes = AES.new(k_enc_byte, AES.MODE_CTR, nonce=nonce)

    # cipherText
    cipher_text = aes.encrypt(bytes(message.encode("utf-8")))

    H_MAC = HMAC.new(k_hmac_byte, digestmod=SHA256)
    # MAC value for our message
    MAC = H_MAC.update(cipher_text).digest()

    # encrypted text
    return int.from_bytes(nonce + cipher_text + MAC, byteorder="big")


def sendMessage(message, message_id):
    keys = readJson("./Keys.json")
    h, s = sign_message(stuID_B, keys["IK_Pri"])

    # get pre-key-bundle
    (OTK_ID_B, IK_Pub_B_x, IK_Pub_B_y, SPK_Pub_B_x, SPK_Pub_B_y,
     h_sign_pre_key, s_sign_pre_key, OTK_B_x, OTK_B_y) = reqKeyBundle(stuID_A, stuID_B, h, s)

    # check verification
    if SignVer(concatenate(SPK_Pub_B_x, SPK_Pub_B_y), h_sign_pre_key, s_sign_pre_key, curve,
               Point(IK_Pub_B_x, IK_Pub_B_y, curve)):
        print("signature verified")
        # generate EK
        EK_Pub, EK_Priv = keyGen()

        # generate Ks
        ks = generate_Ks_sender(Point(IK_Pub_B_x, IK_Pub_B_y, curve), EK_Priv,
                                Point(SPK_Pub_B_x, SPK_Pub_B_y, curve), keys["IK_Pri"], Point(OTK_B_x, OTK_B_y, curve))

        for i in range(message_id):
            K_enc, k_hmac, ks = KDF_Chain(ks)

        cipher_text = encrypt(k_hmac, K_enc, message)
        SendMsg(stuID_A, stuID_B, OTK_ID_B, message_id, cipher_text, keys["IK_Pub_x"], keys["IK_Pub_y"],
                EK_Pub.x,
                EK_Pub.y)
    else:
        print("signature not verified")


def generateOTK(key_id):
    OTKs = readJson("./OTK.json")
    keys = readJson("./Keys.json")
    T = keys["SPK_Pri"] * IKey_Ser_Pub
    U = b'TheHMACKeyToSuccess' + concatenate(T.y, T.x)
    KHMAC = SHA3_256.new(U)
    KHMAC = int(KHMAC.hexdigest(), 16)
    KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length() + 7) // 8, byteorder='big')
    OTK_Pub, OTK_Pri = keyGen()
    hmac = HMAC.new(KHMAC_to_byte, concatenate(OTK_Pub.x, OTK_Pub.y), digestmod=SHA256)
    hmac = hmac.hexdigest()
    OTKReg(key_id, OTK_Pub.x, OTK_Pub.y, hmac)
    OTKs.insert(key_id, {
        'x': OTK_Pub.x,
        'y': OTK_Pub.y,
        'priv': OTK_Pri,
        'hmac': hmac
    })
    updateJson("./OTK.json", OTKs)


def statusCheckAndGenerateNewOTK():
    OTKs = readJson("./OTK.json")
    keys = readJson("./Keys.json")
    h, s = sign_message(stuID_A, keys["IK_Pri"])
    num_message_remain, num_OTK_remain, status_message = Status(stuID_A, h, s)
    if num_message_remain == 0:
        while len(OTKs) > num_OTK_remain:
            OTKs.pop(0)
        updateJson("./OTK.json", OTKs)
        for i in range(10 - num_OTK_remain):
            generateOTK(i)


def decrypt(message, Ks, message_id):
    for i in range(message_id):
        K_enc, K_HMAC, Ks = KDF_Chain(Ks)

    nonce = message[:8]
    cipher_text = message[8:-32]
    MAC = message[-32:]

    decipher = AES.new(K_enc.to_bytes((K_enc.bit_length() + 7) // 8, byteorder='big'), AES.MODE_CTR, nonce=nonce)

    plain_text = decipher.decrypt(cipher_text).decode()

    verify = HMAC.new(K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big'), digestmod=SHA256)
    calculated_mac = verify.update(cipher_text).digest()

    return plain_text, calculated_mac == MAC


def receiveMessageAndDecipher():
    OTKs = readJson("./OTK.json")
    keys = readJson("./Keys.json")
    h, s = sign_message(stuID_A, keys["IK_Pri"])
    sender_id, OTK_id, message_id, message, sender_ik_x, sender_ik_y, EK_x, EK_y = ReqMsg(h, s)
    Ek = Point(EK_x, EK_y, curve)
    sender_pub = Point(sender_ik_x, sender_ik_y, curve)
    Ks = generate_Ks_receiver(OTKs[OTK_id]["priv"], Ek, sender_pub, keys["SPK_Pri"], keys["IK_Pri"])
    message_to_byte = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    plain_text, is_valid = decrypt(message_to_byte, Ks, message_id)
    if is_valid:
        print("Message received: {}".format(plain_text))
        messages.append({"sender_id": sender_id, "message_id": message_id, "message": plain_text})
    else:
        print("message MAC is invalid")


def phase2():
    OTKs = readJson("./OTK.json")
    keys = readJson("./Keys.json")
    h, s = sign_message(stuID_A, keys["IK_Pri"])
    local_messages = dict()
    PseudoSendMsg(h, s)

    for i in range(5):
        sender_id, OTK_id, message_id, message, sender_ik_x, sender_ik_y, EK_x, EK_y = ReqMsg(h, s)
        Ek = Point(EK_x, EK_y, curve)
        sender_pub = Point(sender_ik_x, sender_ik_y, curve)
        Ks = generate_Ks_receiver(OTKs[OTK_id]["priv"], Ek, sender_pub, keys["SPK_Pri"], keys["IK_Pri"])

        message_to_byte = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')

        # since it consists of hash functions i can recreate each key at each iteration
        for i in range(message_id):
            K_enc, K_HMAC, Ks = KDF_Chain(Ks)

        # mac is 32 bytes
        # nonce is 8 bytes
        nonce = message_to_byte[:8]
        MAC = message_to_byte[-32:]
        ciphertext = message_to_byte[8:-32]

        aes = AES.new(K_enc.to_bytes((K_enc.bit_length() + 7) // 8, byteorder='big'), AES.MODE_CTR, nonce=nonce)

        plainText = aes.decrypt(ciphertext).decode()

        # calculate the mac value
        verify = HMAC.new(K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big'), digestmod=SHA256)
        calculated_mac = verify.update(ciphertext).digest()

        # compare mac with the message
        if calculated_mac == MAC:
            Checker(stuID_A, sender_id, message_id, plainText)
            local_messages[message_id] = plainText
        else:  # if mac is wrong
            Checker(stuID_A, sender_id, message_id, "INVALIDHMAC")

    isDeleted = ReqDelMsg(h, s)
    print("--------------------------------------------------")
    print("Checking for deleted messages")
    for key, value in local_messages.items():
        if key in isDeleted:
            print("Message {} - was deleted by sender".format(key))
        else:
            print("Message {}: {}".format(key, value))



def flow():
    keys = readJson("./Keys.json")
    h, s = sign_message(stuID_A, keys["IK_Pri"])
    num_message_remain, num_OTK_remain, status_message = Status(stuID_A, h, s)
    if num_message_remain == 0:
        statusCheckAndGenerateNewOTK()
        PseudoSendMsgPH3(h, s)
    for i in range(5):
        receiveMessageAndDecipher()

    for i in range(len(messages)):
        sendMessage(messages[i]["message"], messages[i]["message_id"])


# PHASE 1
# keys = readJson("./Keys.json")
# h, s = sign_message(stuID_A, keys["IK_Pri"])
# ResetOTK(h, s)
# ResetSPK(h, s)
# ResetIK(keys["rcode"])
#
# registerIK()
# verificationCode = 0
# verifyIKAndRegisterSPKAndOTKs(verificationCode)

# PHASE 2
# phase2()


# PHASE 3
# flow()
