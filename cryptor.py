import sys, os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

if (os.path.exists("encrypt_result") == False):
    os.mkdir("encrypt_result")
if (os.path.exists("decrypt_files") == False):
    os.mkdir("decrypt_files")

if len(sys.argv) == 1:
    print("Set the operating mode! Example: \"python cryptor.py [operating mode]\".")
    print("Режимы работы:")
    print("   1) e - Encrypt text.")
    print("   2) d - Decrypt text.")

    exit()
else:
    if sys.argv[1] == "e":
        encrypt_mode = True
    elif sys.argv[1] == "d":
        encrypt_mode = False
    elif sys.argv[1] == "m":
        print("Operating modes:")
        print("   1) e - Encrypt text.")
        print("   2) d - Decrypt text.")
        print("Example: \"python cryptor.py [operating mode]\".")

        exit()
    else:
        print("Set the operating mode! Example: \"python cryptor.py [operating mode]\".")
        print("Operating modes:")
        print("   1) e - Encrypt text.")
        print("   2) d - Decrypt text.")

        exit()

if (encrypt_mode == True):
    text = input("Text: ").encode('utf-8')
    code = input("Key: ")
    key = RSA.generate(2048)

    encrypted_key = key.exportKey(
        passphrase=code, 
        pkcs=8, 
        protection="scryptAndAES128-CBC"
    )

    with open('encrypt_result/rsa_private.bin', 'wb') as f:
        f.write(encrypted_key)

    with open('encrypt_result/rsa_public.pem', 'wb') as f:
        f.write(key.publickey().exportKey())

    with open('encrypt_result/data.bin', 'wb') as out_file:
        recipient_key = RSA.import_key(
            open('encrypt_result/rsa_public.pem').read()
        )
        
        session_key = get_random_bytes(16)
        
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        data = text
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        
        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)
else:
    code = input("Key: ")
    
    with open('decrypt_files/data.bin', 'rb') as fobj:
        private_key = RSA.import_key(
            open('decrypt_files/rsa_private.bin').read(),
            passphrase=code
        )
        
        enc_session_key, nonce, tag, ciphertext = [
            fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]
        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
     
    print("Result: " + data.decode('utf-8'))
