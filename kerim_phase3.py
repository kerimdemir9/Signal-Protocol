import math
import random

from Crypto.Cipher import AES
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto import Random
import Phase3.phase3_Client_basic as helper

stuID_A = 28853
stuID_B = 28928
curve = Curve.get_curve('secp256k1')
n = curve.order
p = curve.field
P = curve.generator
a = curve.a
b = curve.b

IK_Pub = Point(99729665936069400189049630025268145612680094240728273595298801806858959619148,
               51191321905177615780693558879744615245596224651621976306951564536010637931746, curve)
IK_Pri = 68708997509867735893754012737457161590792631113345894906193292191370424524695

SPK_Pub = Point(66331158853220778162825121078733586816456999454427083347515179674153920143331,
                45084201860451134626463936478291283412349276620097950808674494591713342720848, curve)
SPK_Pri = 51684599043567019427791939180673528490623665420756140617689541185560822669121

OTKs = [
    {
        'x': 44255398804583204481043701672860692477886392723206229799655503561787212780534,
        'y': 51323807639268791711894206811723690808760980368858268907678537638774830649447,
        'priv': 51513326303051302006769008648720998759160465114279750591027883327672795888058,
        'hmac': '58fdb1279d99653c743161eab9324fdd4d7ba7ddb6aa986d1e07d9f33f9862fb'
    },
    {
        'x': 21730107469109736390624604290554907124362126115910607381390129576112122967642,
        'y': 104662274509805720852728583126365762123060134673725406549442155935629241404791,
        'priv': 5344355808956078712432193772065388733035611113465183300113325668800436818789,
        'hmac': '879cf7d30c6d9e90f2e01c222eeebf4d8547c740b5a75c3f008142a12d568c9b'
    },
    {
        'x': 59755237523901120384689639954119323728331174482239593835365574556629231711759,
        'y': 74300422596745436327625689029615796409812773615772745388247486295936145617461,
        'priv': 35134549051490170781378830613395103347455086723290974920322803954923299739088,
        'hmac': 'ac9fc7374435c8705ef948d1c17e6b67f0feeba760f02eb31096959ea9c03503'
    },
    {
        'x': 61545429311932603573466990676061123900877215427529538374361775978494510554315,
        'y': 8257959231206780085388072693635253661211716253878962853700213136548950036855,
        'priv': 95511789176498480970209657222895481350116187657206403146779584298404459241262,
        'hmac': '25ffa94f70f19442ed745b379ec4c859466b691be25fbb1856995f0933334320'
    },
    {
        'x': 63601419957970267267984741735107345591319849302901301196272822042864048692891,
        'y': 86949831158675795869783625893416782174731202074759026542959050612121761478833,
        'priv': 108464628310087413120014596684623268248586067675986305841138404839071477172230,
        'hmac': '453840cb3035a2ee0fe8b1af7a7f0790cc6260838c7698874234ab9e9b2a6e1e'
    },
    {
        'x': 81289474424337022307620381892796081151085972360070649457325984765212761430010,
        'y': 86774671132541065633673462935177369141276924214597395913310036171267264644718,
        'priv': 50319733310065434494542862831959821232648712326840705601025232283935126130685,
        'hmac': 'c3b4711f23d731ae8e432239eac8b0ebe80c810f7cd0709172ac962fbea0a2f3'
    },
    {
        'x': 47456134413527556749096303557016520683364453344989557614944381947074593367450,
        'y': 101219456453782938842206977916441703798759459056821245686253586069668006559505,
        'priv': 50687790312351454804412294016971201129089072958693519598146874000992981870351,
        'hmac': '94e1041be7eb0e216bbcff08db9e13f8ce2c590cfb62ddb1be749191715a0ea5'
    },
    {
        'x': 40244660907375988572375775586570136281938190095191956072153197612143722651249,
        'y': 80864721028602210145413511228360680631041301465878353868238460148080214267452,
        'priv': 35534550521786368436926134012705204811083970336487954778045558581596047749400,
        'hmac': '3f78f87353c5527f1d55b2a554a9799bac71628cff05ca4a37cca4399832a01c'
    },
    {
        'x': 42666788615985813411966879528790671933839295030976884089354076802729679911387,
        'y': 67313892425190120125879045936054283574018078586911655764648906945383289805599,
        'priv': 26656539776457566413019517492568416816618811249760679138737165269674761340864,
        'hmac': 'd95ba95e6fce9af374b0797086c2a17d349d5e6b9e4c29727b1f71ee4377684e'
    },
    {
        'x': 75675674187751096192464462123239358767196787495359031146578060936282560333414,
        'y': 19338940150178888168923446531814691513924377909391455098551787631232400615954,
        'priv': 56607046805226084885771759028035999541626320435014911543388033464422398851137,
        'hmac': 'db35b6f2c1017bf7ea76074da74b5a723d5bdbc9e382007fe6be9832e4a0f876'
    },
]


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
    T1 = IK_Pub_b * Ek_Pri_sender
    T2 = SPK_Pub_b * Ek_Pri_sender
    T3 = OTK_Pub_b * Ek_Pri_sender
    T4 = SPK_Pub_b * IK_Pri_sender
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
    # random 8 byte nonce
    nonce = random.randint(2 ** 63, 2 ** 64 - 1)
    nonce_to_byte = nonce.to_bytes((nonce.bit_length() + 7) // 8, byteorder='big')

    # encryption algorithm
    aes = AES.new(k_enc.to_bytes((k_enc.bit_length() + 7) // 8, byteorder='big'), AES.MODE_CTR, nonce=nonce_to_byte)

    # cipherText
    cipher_text = aes.encrypt(bytes(message.encode("utf-8")))

    H_MAC = HMAC.new(k_hmac.to_bytes((k_hmac.bit_length() + 7) // 8, byteorder="big"), msg=cipher_text,
                     digestmod=SHA256)
    # MAC value for our message
    MAC = ((int.from_bytes(H_MAC.digest(), byteorder="big") % n)  # so that it is inside the curve
           .to_bytes(((int.from_bytes(H_MAC.digest(), byteorder="big") % n).bit_length() + 7) // 8, byteorder='big'))
    # encrypted text
    return int.from_bytes(nonce_to_byte + cipher_text + MAC, byteorder="big")


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

        for i in range(OTK_ID_B):
            K_enc, K_HMAC, ks = KDF_Chain(ks)

        cipher_text = encrypt(K_HMAC, K_enc, message)
        helper.SendMsg(stuIDA, stuIDB, OTK_ID_B, message_id, cipher_text, IK_Pub.x, IK_Pub.y, EK_Pub.x, EK_Pub.y)
    else:
        print("signature not verified")


def statusCheck():
    h, s = sign_message(stuID_A, IK_Pri)
    helper.Status(stuID_A, h, s)


statusCheck()















