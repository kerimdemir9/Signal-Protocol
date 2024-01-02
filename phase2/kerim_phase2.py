from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
from Crypto.Cipher import AES
import phase2_Client_basic as helper
from Crypto import Random
import math


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

IK_Pub = Point(99729665936069400189049630025268145612680094240728273595298801806858959619148,
               51191321905177615780693558879744615245596224651621976306951564536010637931746, curve)
IK_Pri = 68708997509867735893754012737457161590792631113345894906193292191370424524695

SPK_Pub = Point(66331158853220778162825121078733586816456999454427083347515179674153920143331,
                45084201860451134626463936478291283412349276620097950808674494591713342720848, curve)
SPK_Pri = 51684599043567019427791939180673528490623665420756140617689541185560822669121

# can be obtained by executing phase 1
OTKs = [
    {
        'x': 8626803991917323951188578128988320515097610182179926290687215575159426528171,
        'y': 22534848478398837095643581083439697690511665846017507803472232406493198695382,
        'priv': 38076480630973602457917518807274724578471647676959651623818019379931487951701,
        'hmac': "89475faa277a9cc84155ef1bb2dbddb33f13d844bfbcba6be0c2d7d855c7e9c6"
    },
    {
        'x': 77439160308637751110683092236556822048430915099400174970291621537031385929721,
        'y': 87266865024633640606516265723507666234710766527784236846663097064177723351527,
        'priv': 7708875003188210791293017402344038908699103692815239768005890734197652833884,
        'hmac': "bbcd07bb7c9a81944a897ead8b8cadaa47909810f14d0eb5117e4d5e9352de9d"
    },
    {
        'x': 94137172876983411346141947975070150523800673432422172422277301993199998439431,
        'y': 16625955381011709990455436037758492358707993971712007540474122579188315137658,
        'priv': 2316666169657817459888738842591482045488277151801738782661559873579375428519,
        'hmac': "8037207d7f659190fc9fa987a10e2f86c7de22d72ed272bed55f3e164dbcc1dc"
    },
    {
        'x': 3487292096495394151480815819233056790217061536277965279993747302130137733196,
        'y': 108370912813446415069789369042386201420943563210326959542380000660140242960889,
        'priv': 20464463156379499935372319376315934226614704873804959651698238940816747838815,
        'hmac': "27fbcfbc347b3566ea5b7aad7289b2279e36ba63c3f52a3e46449a509c4c70db"
    },
    {
        'x': 25103203025677840363968748888076268825016613344764030982290180145881307917031,
        'y': 102415615662504300250381051494484404612683625411805664464756441209350744211246,
        'priv': 102498900110139034435775127472782357084326000909029294952264534555668908272520,
        'hmac': "d0325330b26c4dc8577263e82967fe1df4d167c964188f956ac9d4d2977b717f"
    },
    {
        'x': 22936535991802235127717300468437022853631773856383730415078863103536214354304,
        'y': 104128072787761757289239262420918018305046770012498468510728969176117678211758,
        'priv': 85186823280723796919719737984316028998474066615244310928381872481312233335108,
        'hmac': "a10504150a1ca453c46f4ac963581b24fd9594965130b63ee420152dc838a5b3"
    },
    {
        'x': 28782195404314855618142008008548021157824782875284334669620580299084636309661,
        'y': 25602476718179021860066918137201642106298977327967254928493916937447215370486,
        'priv': 52655803084578301242616940746313241863906022967710533515007340851929403090877,
        'hmac': "d90305024212e0485e43998e05e564d7dba2f3c8321c954e73ccdd276af54811"
    },
    {
        'x': 107637601825137883335571394395497425196193263746163279848366687997089739217084,
        'y': 114049415797904200024944168276831083947210403585514432532234485815808071775686,
        'priv': 108627503734281718235049663042370654465926109046312421122947903243488528720625,
        'hmac': "e5101c46a406102c1229f99ffd9d0ba49bd75c12a4641ee07ca582fe50fc03b9"
    },
    {
        'x': 80845651990513997962334277172656575498869415377709956152061848204432208836894,
        'y': 21320946632181719942641598748919601268436051725318380096100710504604856292425,
        'priv': 66427526122705486326827459558834628276747709333610431220327304379218633666032,
        'hmac': "7015037d9c1c0a5e0b3fc3b51bf91967a207adbc84c9bbd453012e36062c7cf6"
    },
    {
        'x': 77845061600678677835219194423538079795037413589898558555408888704067003588328,
        'y': 41182234232321952483976187339098572404999125655387845012668628663666235402290,
        'priv': 51732203199286390689138257332966675410877794083304340104328260095119831267307,
        'hmac': "885d3f27ce50fb4b01a4d19d94427d02236c71384a20b1150e30f4c077e05726"
    },
]

# this will make client send 5 messages to my inbox
h, s = sign_message(helper.stuID, IK_Pri)
helper.PseudoSendMsg(h, s)

messages = dict()


for i in range(5):
    sender_id, OTK_id, message_id, message, sender_ik_x, sender_ik_y, EK_x, EK_y = helper.ReqMsg(h, s)
    Ek = Point(EK_x, EK_y, curve)
    sender_pub = Point(sender_ik_x, sender_ik_y, curve)
    Ks = generate_Ks(OTKs[OTK_id]["priv"], Ek, sender_pub, SPK_Pri, IK_Pri)

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
        helper.Checker(helper.stuID, sender_id, message_id, plainText)
        messages[message_id] = plainText
    else:  # if mac is wrong
        helper.Checker(helper.stuID, sender_id, message_id, "INVALIDHMAC")

isDeleted = helper.ReqDelMsg(h, s)
print("--------------------------------------------------")
print("Checking for deleted messages")
for key, value in messages.items():
    if key in isDeleted:
        print("Message {} - was deleted by sender".format(key))
    else:
        print("Message {}: {}".format(key, value))
