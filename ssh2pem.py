from base64 import b64decode,b64encode
from Crypto.PublicKey import RSA
from sympy import isprime
file = "id_rsa"
with open(file,"r") as f:
    lines = list(f)
    b64 = ''.join(line[:-1] for line in lines[1:-1])
    b64d = b64decode(b64)
ver = b64d[:15]
clen = int.from_bytes(b64d[15:15+4],'big')
cname = b64d[15+4:15+4+clen]
b64d = b64d[19+clen:]
len = int.from_bytes(b64d[:4],'big')
kdfn = b64d[4:4+len]
b64d = b64d[4+len:]
len = int.from_bytes(b64d[:4],'big')
kdf = b64d[4:4+len]
b64d = b64d[4+len:]
keylen = int.from_bytes(b64d[:4],'big')
# keyn = int.from_bytes(b64d[4:4+keylen],'big')
b64d = b64d[4:]
pb_block = int.from_bytes(b64d[:4],'big')
pbkey = b64d[4:4+pb_block]
priv = b64d[16+pb_block:] #escape for comment+pad+checksum
tlen = int.from_bytes(pbkey[:4],'big')
type = pbkey[4:4+tlen]
if type != b'ssh-rsa':
    print("Only support ssh-rsa")
    exit(1)
len = int.from_bytes(priv[:4],'big')
pri_type = priv[4:4+len]
if pri_type != b'ssh-rsa':
    print("Only support ssh-rsa")
    exit(1)
priv = priv[4+len:]
len = int.from_bytes(priv[:4],'big')
pub0 = int.from_bytes(priv[4:4+len],'big') # n
priv = priv[4+len:]
len = int.from_bytes(priv[:4],'big')
pub1 = int.from_bytes(priv[4:4+len],'big') # e
priv = priv[4+len:]
len = int.from_bytes(priv[:4],'big')
pri0 = int.from_bytes(priv[4:4+len],'big') # d
rsa = RSA.construct((pub0,pub1,pri0))
with open("id_rsa.pem",'w') as w:
    w.write(rsa.export_key().decode())