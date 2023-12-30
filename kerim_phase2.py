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

OTKs = [
    {
        'x': 11340186422798999858817534337300138723348010236409782750151768133720886815431,
        'y': 65886240280400413344152283634696689690063732800846693304246328927625260388918,
        'priv': 26401887361690537408414180589836485411257227981656605318168964023307224708353,
        'hmac': "48da8155ab30546d7c6ab00f797bd6d112e1526d3f8b0d62ee2fd05de713ef0b"
    },
    {
        'x': 96636097287251919507866186294349613179244165594507468056775450074111323053517,
        'y': 26033204375905469157763197738506149910142499461659362761874874395478180021269,
        'priv': 60497881481957961259802866086853412920849061238145857944209781974971417650385,
        'hmac': "086bee8c3bb64c4363260cfb48d64c47a1675e0a0019888727ae1ffbf6051bc4"
    },
    {
        'x': 35903622813406809940977505027651122831016092234141951452031609792843834299235,
        'y': 20319352567230564081581298996724281267257360129573973226426670856047096998818,
        'priv': 109913621107577993781648415150719158871484344444595470990769775105427008147804,
        'hmac': "b94bd505ce98575e05c946397c3817cc79a9a41fe1d39688fd676c6c4c281fdc"
    },
    {
        'x': 22810495957211159490510584228361638113891353540339549082015803509413044666240,
        'y': 26938601301247943709805548725034344756572096955590197220888955940735056322905,
        'priv': 104179707344757829918021982174834149484615809013930388557727752359224937099663,
        'hmac': "2bfe5993fbecf442b7f6dcc6764f23bf9c5e87c11d59bfa3710fd896bd1103b8"
    },
    {
        'x': 112525540360416366187383484388702651067511207676813045292490417675431282792065,
        'y': 7152172423355671240238011333145638749798613577078323152094970043123736818445,
        'priv': 30640584663084340947798009655875920582406694545366929434843791820543505310366,
        'hmac': "7991d079b0a660f20434af627be0a2505a974d6165d5b70bcd6985643024c3cd"
    },
    {
        'x': 81031723234904261666588960325472391926389568527311160852371209611622788187865,
        'y': 104631289291958022626522442806539297584788854623593149245125679953366634825118,
        'priv': 73805640279178297175729648044042264276750996946740811872432401395462638584024,
        'hmac': "94f1cf2c38043fd9909d9944052babb94c7772f6397a91c8846ab5851581c090"
    },
    {
        'x': 83979340073267352811549234800162007844208504201665592392920649478238942496330,
        'y': 36621447743855875375951316290899044216772488103764093443471664662016469761214,
        'priv': 86370645301539345753298317033569334246695868123944736125208471207282223150501,
        'hmac': "b24570cccaa446e5b84c5aa3e023b4604d571b205db6ef1bfbd318bfbbe8f9b8"
    },
    {
        'x': 8447904888941059289043591805971198027183446178949850988071843201145309994200,
        'y': 57490359722032665516804422736223467152045182030661681310502034255937308232847,
        'priv': 14333704304740954660640146225134083988596227390374111527966152250301925624405,
        'hmac': "e784822d1e1551ae2133d01cb56d2dd01e5525cbef5c77143aecca3fb226aba0"
    },
    {
        'x': 16565489544115446659180318054654839266603959350673403178228394690921533864484,
        'y': 71183111092055108070412780751400110733394468326555851952797030880685804228901,
        'priv': 31556240777732434936304978778336976102210152210328797009625564237131028145437,
        'hmac': "3486e48ffbbf50c0de9bd73e43a76038d3ed1473f3fd30d5b91e6bdbdbd0c015"
    },
    {
        'x': 95321662379080185494395305491099702888222519758403413257448701285379774809282,
        'y': 26133498806693863810417746571600633193930144863284488988472488060433528708561,
        'priv': 76449000618924181790404301845861450573332638846535570487809446011449252805125,
        'hmac': "bf5b61ec35a18cfebcee4ebde42324e0d5776abcbadedb66567ae9d597542fed"
    },
]

# this will make client send 5 messages to my inbox
h, s = sign_message(helper.stuID, IK_Pri)
helper.PseudoSendMsg(h, s)

messages = []

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
    ciphertext = message_to_byte[8:-32]
    MAC = message_to_byte[-32:]

    aes = AES.new(K_enc.to_bytes((K_enc.bit_length() + 7) // 8, byteorder='big'), AES.MODE_CTR, nonce=nonce)

    plainText = aes.decrypt(ciphertext).decode()

    # calculate the mac value
    verify = HMAC.new(K_HMAC.to_bytes((K_HMAC.bit_length() + 7) // 8, byteorder='big'), digestmod=SHA256)
    calculated_mac = verify.update(ciphertext).digest()

    # compare mac with the message
    if calculated_mac == MAC:
        helper.Checker(helper.stuID, sender_id, message_id, plainText)
        messages.append(plainText)
    else:  # if mac is wrong
        helper.Checker(helper.stuID, sender_id, message_id, "INVALIDHMAC")

isDeleted = helper.ReqDelMsg(h, s)
print("--------------------------------------------------")
print("Checking for deleted messages")
for i in range(len(messages)):
    if i + 1 in isDeleted:
        print("Message {} - was deleted by sender".format(i+1))
    else:
        print("Message {}: {}".format(i+1, messages[i]))
