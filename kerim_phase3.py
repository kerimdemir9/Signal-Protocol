import math
import json
from Crypto.Cipher import AES
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random
import Phase3.phase3_Client_basic as helper
import secrets


stuID_A = 28853
# stuID_B = 28928
stuID_B = 28853
curve = Curve.get_curve('secp256k1')
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b

IK_Pub = Point(99729665936069400189049630025268145612680094240728273595298801806858959619148,
               51191321905177615780693558879744615245596224651621976306951564536010637931746, curve)
IK_Pri = 68708997509867735893754012737457161590792631113345894906193292191370424524695

IKey_Ser_Pub = Point(int("1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9", 16),
                     int("ce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff", 16), curve)

SPK_Pub = Point(66331158853220778162825121078733586816456999454427083347515179674153920143331,
                45084201860451134626463936478291283412349276620097950808674494591713342720848, curve)
SPK_Pri = 51684599043567019427791939180673528490623665420756140617689541185560822669121


def readJson():
    file_name = './Phase3/OTK.json'
    with open(file_name, 'r') as file:
        OTK = json.load(file)
    return OTK


def updateJson(data):
    with open('./Phase3/OTK.json', 'w') as file:
        json.dump(data, file, indent=4)


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


def sendMessage(stuIDA, stuIDB, message, message_id):
    h, s = sign_message(stuID_B, IK_Pri)

    # get pre-key-bundle
    (OTK_ID_B, IK_Pub_B_x, IK_Pub_B_y, SPK_Pub_B_x, SPK_Pub_B_y,
     h_sign_pre_key, s_sign_pre_key, OTK_B_x, OTK_B_y) = helper.reqKeyBundle(stuID_A, stuID_B, h, s)

    # check verification
    if helper.SignVer(concatenate(SPK_Pub_B_x, SPK_Pub_B_y), h_sign_pre_key, s_sign_pre_key, curve,
                      Point(IK_Pub_B_x, IK_Pub_B_y, curve)):
        print("signature verified")
        # generate EK
        EK_Pub, EK_Priv = keyGen()

        # generate Ks
        ks = generate_Ks_sender(Point(IK_Pub_B_x, IK_Pub_B_y, curve), EK_Priv,
                                Point(SPK_Pub_B_x, SPK_Pub_B_y, curve), IK_Pri, Point(OTK_B_x, OTK_B_y, curve))

        for i in range(message_id):
            K_enc, k_hmac, ks = KDF_Chain(ks)

        cipher_text = encrypt(k_hmac, K_enc, message)
        helper.SendMsg(stuIDA, stuIDB, OTK_ID_B, message_id, cipher_text, IK_Pub.x, IK_Pub.y, EK_Pub.x, EK_Pub.y)
    else:
        print("signature not verified")


def generateOTK(key_id):
    OTKs = readJson()
    T = SPK_Pri * IKey_Ser_Pub
    U = b'TheHMACKeyToSuccess' + concatenate(T.y, T.x)
    KHMAC = SHA3_256.new(U)
    KHMAC = int(KHMAC.hexdigest(), 16)
    KHMAC_to_byte = KHMAC.to_bytes((KHMAC.bit_length() + 7) // 8, byteorder='big')
    OTK_Pub, OTK_Pri = keyGen()
    hmac = HMAC.new(KHMAC_to_byte, concatenate(OTK_Pub.x, OTK_Pub.y), digestmod=SHA256)
    hmac = hmac.hexdigest()
    helper.OTKReg(stuID_A, key_id, OTK_Pub.x, OTK_Pub.y, hmac)
    OTKs.insert(key_id, {
        'x': OTK_Pub.x,
        'y': OTK_Pub.y,
        'priv': OTK_Pri,
        'hmac': hmac
    })
    updateJson(OTKs)


def statusCheckAndGenerateNewOTK():
    OTKs = readJson()
    h, s = sign_message(stuID_A, IK_Pri)
    num_message_remain, num_OTK_remain, status_message = helper.Status(stuID_A, h, s)
    if num_message_remain == 0:
        while len(OTKs) > num_OTK_remain:
            OTKs.pop(0)
        updateJson(OTKs)
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


messages = []


def receiveMessageAndDecipher():
    OTKs = readJson()
    sender_id, OTK_id, message_id, message, sender_ik_x, sender_ik_y, EK_x, EK_y = helper.ReqMsg(stuID_A, h, s)
    Ek = Point(EK_x, EK_y, curve)
    sender_pub = Point(sender_ik_x, sender_ik_y, curve)
    Ks = generate_Ks_receiver(OTKs[OTK_id]["priv"], Ek, sender_pub, SPK_Pri, IK_Pri)
    message_to_byte = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    plain_text, is_valid = decrypt(message_to_byte, Ks, message_id)
    if is_valid:
        print("Message received: {}".format(plain_text))
        messages.append({"sender_id": sender_id, "message_id": message_id, "message": plain_text})
    else:
        print("message MAC is invalid")


# GENERATE NEW OTKs ONLY WHEN YOU DONT HAVE ANY MESSAGES IN YOUR MAILBOX
h, s = sign_message(stuID_A, IK_Pri)
# helper.PseudoSendMsgPH3(stuID_A, h, s)
# num_message_remain, num_OTK_remain, status_message = helper.Status(stuID_A, h, s)
# sendMessage(stuID_A, stuID_B, "Nasılsın", 2)
# statusCheckAndGenerateNewOTK()
receiveMessageAndDecipher()


def flow():
    h, s = sign_message(stuID_A, IK_Pri)
    helper.PseudoSendMsgPH3(stuID_A, h, s)
    for i in range(5):
        receiveMessageAndDecipher()

    for i in range(len(messages)):
        sendMessage(stuID_A, stuID_B, messages[i]["message"], messages[i]["message_id"])

# flow()