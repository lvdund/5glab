import hashlib

rand = bytes.fromhex("992a1479ac677dbc9298c0b641210500")
resStar = bytes.fromhex("81e822bcae4dda7da0cd92448dab046b")


h = hashlib.sha256(rand + resStar).digest()

print("SHA256 full:", h.hex())
print("first16    :", h[:16].hex())  
print("last16     :", h[16:].hex())  

