from random import randint, seed
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random

API_URL = 'http://harpoon1.sabanciuniv.edu:9999/'

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E

def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(0,n)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = 1748178 #randint(0,n-2)
    R = k * P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (k - sA*h) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x%n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

stuID = 11111 # Enter your ID
# Create a long term key
curve = Setup()
IKey_Pr = random.randint(1, curve.order)
P = curve.generator
IKey_Pub = IKey_Pr * P 
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441 , 93192522080143207888898588123297137412359674872998361245305696362578896786687, curve)

def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

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
    print(response.json())

############## The new functions of phase 2 ###############
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]

def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

###########################################################

print("My ID number is",stuID)

print("Converted my ID to bytes in order to sign it:",stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'))
h, s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'), curve, IKey_Pr)

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Signature of my ID number is:\nh=",h,"\ns=",s)

print("+++++++++++++++++++++++++++++++++++++++++++++")


print("Sending signature and my IKEY to server via IKRegReq() function in json format")
IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)

print("Received the verification code through email")

print("+++++++++++++++++++++++++++++++++++++++++++++")

code = int(input("Enter verification code which is sent to you: "))

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Sending the verification code to server via IKRegVerify() function in json format")
IKRegVerify(code)

print("+++++++++++++++++++++++++++++++++++++++++++++")

print("Generating SPK...")
SPK_Pr, SPK_Pub = KeyGen(curve)
print("Private SPK: {}\nPublic SPK.x: {}\nPublic SPK.y: {}".format(SPK_Pr, SPK_Pub.x, SPK_Pub.y))
print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them")

toSign = SPK_Pub.x.to_bytes((SPK_Pub.x.bit_length()+7)//8, byteorder='big')+SPK_Pub.y.to_bytes((SPK_Pub.y.bit_length()+7)//8, byteorder='big')
print("Result will be like:", toSign)

print("+++++++++++++++++++++++++++++++++++++++++++++")

h, s = SignGen(toSign, curve, IKey_Pr)
print("Signature of SPK is:\nh=",h,"\ns=",s)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")

print("\n+++++++++++++++++++++++++++++++++++++++++++++")

SPKReg(h,s, SPK_Pub.x,SPK_Pub.y)


print("Creating HMAC key (Diffie Hellman)")

T = SPK_Pr*IKey_Ser
print("T is ", T)
U = b'TheHMACKeyToSuccess' + (T.y).to_bytes(((T.y).bit_length() + 7) // 8, byteorder='big') + (T.x).to_bytes(((T.x).bit_length() + 7) // 8, byteorder='big')
print("U is ", U)
K_hmac = SHA3_256.new(U).digest()
print("HMAC key is created ", K_hmac)
OTKs = {}
print("\n+++++++++++++++++++++++++++++++++++++++++++++")
print("Creating OTKs starting from index 0...")
for i in range(11):
    s, Q = KeyGen(curve)
    OTKs[i] = [s, Q.x, Q.y]
    print("{}th key generated. Private part={}\nPublic (x coordinate)={}\nPublic (y coordinate)={}".format(i,s, Q.x, Q.y))
    h = HMAC.new(K_hmac, digestmod=SHA256)
    print("x and y coordinates of the OTK converted to bytes and concatanated")
    message = Q.x.to_bytes((Q.x.bit_length()+7)//8, byteorder='big')+Q.y.to_bytes((Q.y.bit_length()+7)//8, byteorder='big')
    print("Message", message)
    h.update(message)
    hmac_ = h.hexdigest()
    print("HMAC is calculated and converted with 'hexdigest()': ")
    print(hmac_)
    isRegistered = OTKReg(i,Q.x,Q.y,hmac_)
    if(isRegistered): continue
    else: break

print("\nOTK keys were generated successfully!")

print("\nChecking the inbox for incoming messages \n+++++++++++++++++++++++++++++++++++++++++++++\n")
print("\nSigning my stuID with my private IK\n")
print("In signature generation I fixed the random variable to 1748178 so that you can re-generate if you want\n")
h, s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'), curve, IKey_Pr)
print("")

PseudoSendMsg(h,s)

col_msgs = {}
mal_id = 0

print("\n+++++++++++++++++++++++++++++++++++++++++++++\n")

for i in range(5):
    idb, otkID, msgID, message, ikx, iky, ekx, eky =ReqMsg(h,s)

    print("I got this from client {}: \n {}".format(idb, message))
    message = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    print("Converting message to bytes to decrypt it...\nConverted message is:\n", message)
    
    nonce = message[:8]
    ctext = message[8:-32]
    hmac = message[-32:]

    print("Generating the key Ks, Kenc, & Khmac and then the HMAC value ..")
    T1 = Point(ikx, iky, curve) * SPK_Pr
    T2 = Point(ekx, eky, curve) * IKey_Pr
    T3 = Point(ekx, eky, curve) * SPK_Pr
    T4 = Point(ekx, eky, curve) * OTKs[otkID][0]
    
    #print("T is: \n", T)
    U = (T1.x).to_bytes(((T1.x).bit_length() + 7) // 8, byteorder='big') +(T1.y).to_bytes(((T1.y).bit_length() + 7) // 8, byteorder='big')+(T2.x).to_bytes(((T2.x).bit_length() + 7) // 8, byteorder='big') +(T2.y).to_bytes(((T2.y).bit_length() + 7) // 8, byteorder='big')+(T3.x).to_bytes(((T3.x).bit_length() + 7) // 8, byteorder='big') +(T3.y).to_bytes(((T3.y).bit_length() + 7) // 8, byteorder='big')+(T4.x).to_bytes(((T4.x).bit_length() + 7) // 8, byteorder='big') +(T4.y).to_bytes(((T4.y).bit_length() + 7) // 8, byteorder='big')+ b'WhatsUpDoc'

    #print("U is: \n", U)    
    Ks = SHA3_256.new(U).digest()
    #print("Ks is: \n", Ks)
    Kenc = SHA3_256.new(Ks+b'JustKeepSwimming').digest()
    #print("Kenc1 is: \n", Kenc)
    Khmac = SHA3_256.new((Ks+Kenc)+b'HakunaMatata').digest()
    #print("Khmac1 is: \n", Khmac)
    Kkdf = SHA3_256.new((Kenc+Khmac)+b'OhanaMeansFamily').digest()
    #print("Kkdf1 is: \n", Kkdf)
    
    for i in range(1, msgID):
        Ks = Kkdf
        Kenc = SHA3_256.new(Ks+b'JustKeepSwimming').digest()
        #print("Kenc2 is: \n", Kenc)
        Khmac = SHA3_256.new((Ks+Kenc)+b'HakunaMatata').digest()
        #print("Khmac2 is: \n", Khmac)    
        Kkdf = SHA3_256.new((Kenc+Khmac)+b'OhanaMeansFamily').digest()
        #print("Kkdf2 is: \n", Kkdf)

    h_ = HMAC.new(Khmac, digestmod=SHA256)
    h_.update(ctext)
    hmac_ = h_.digest()
    print("hmac is: ", hmac_)
    print()
    if(hmac_ == hmac):
        print("Hmac value is verified")
        cipher = AES.new(Kenc, AES.MODE_CTR, nonce = nonce)
        ptext = cipher.decrypt(ctext).decode("utf8")
        print("The collected plaintext: ", ptext)
        col_msgs[msgID] = ptext
        Checker(stuID, idb, msgID, ptext)
    else:
        print("Hmac value couldn't be verified")
        Checker(stuID, idb, msgID, "INVALIDHMAC")
        mal_id = msgID

    print("\n+++++++++++++++++++++++++++++++++++++++++++++")


ids = ReqDelMsg(h, s)

print("Checking whether there were some deleted messages!! \n==========================================")
if mal_id in ids:
    print("The non-verified message was already discarded!")

for id, msg in col_msgs.items():

    if id in ids:
        print("Message {} - Was deleted by sender - X".format(id))
    else:
        print(("Message {} - "+col_msgs[id]+" - Read").format(id))



print("Trying to delete OTKs...")
h, s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'), curve, IKey_Pr)
ResetOTK(h,s)

print("Trying to delete SPK...")
h, s = SignGen(stuID.to_bytes((stuID.bit_length()+7)//8, byteorder='big'), curve, IKey_Pr)
ResetSPK(h,s)

print("Trying to delete Identity Key...")
rcode = int(input("Enter reset code which is sent to you: "))
ResetIK(rcode)
