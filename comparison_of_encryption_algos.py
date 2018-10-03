"""
This program compares the runtimes of Encryption and Hashing algorithms.

:Author: Varun Nagaraj
:UB Person Number: 50290761
"""

import os
import datetime


def question_1a_1b_1c(file_name, output_file, mode, key_size, file_size):
    """
    This code section deals with AES encryption
    :param file_name: Input File name
    :param output_file: Output file name
    :param mode: CBC/CTR mode supported in this
    :param key_size: Size of the key in bits
    :param file_size: file size in Bytes
    """
    content = ""
    if os.path.exists(file_name):
        fo = open(file_name, 'rb')
        content = fo.read()
        fo.close()

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    start = datetime.datetime.now()
    backend = default_backend()
    key_start = datetime.datetime.now()
    key = os.urandom(key_size)
    print("Time taken for Key Gen:{}".format((datetime.datetime.now() - key_start).total_seconds()))
    iv = os.urandom(16)
    print("encrypting using {} mode".format(mode))
    if mode == "CBC":
        mode = modes.CBC(iv)
    elif mode == "CTR":
        mode = modes.CTR(iv)
    else:
        raise Exception("Not supported Mode type")
    cipher = Cipher(algorithms.AES(key), mode, backend=backend)
    encr_start = datetime.datetime.now()
    encryptor = cipher.encryptor()
    ct = encryptor.update(content)
    fo = open(output_file, 'wb')
    fo.write(ct)
    fo.close()
    encr_time = datetime.datetime.now() - encr_start
    print("Encryption total time taken: {}".format(encr_time.total_seconds()))
    print("Time taken in seconds per byte for encryption is {}".format(encr_time.total_seconds() / file_size))

    decipher = Cipher(algorithms.AES(key), mode, backend=backend)
    decr_start = datetime.datetime.now()
    decryptor = decipher.decryptor()
    pt = decryptor.update(ct)
    fo = open(file_name + "decrypted.file", 'wb')
    fo.write(pt)
    fo.close()
    decr_time = datetime.datetime.now() - decr_start
    print("Decryption total time taken: {}".format(decr_time.total_seconds()))
    fo = open(file_name + "decrypted.file", 'rb')
    pt_final = fo.read()
    print("The bool value for equality of plaintext and decrypted ciphertext is : {}".format(pt_final == content))
    decry_time = datetime.datetime.now() - start
    print("Total time taken in seconds: {}".format(decry_time.total_seconds()))
    print("Time taken in seconds per byte for decryption is {}\n".format(
        decry_time.total_seconds() / file_size))


def question_1d(file_name, hash_algorithm, file_size):
    """
    This code deals with the various hashing algorithms which are given as input
    :param file_name: Input file name
    :param hash_algorithm: Hashing algorithm instance
    :param file_size: Size of the file in Bytes
    """
    print("\nUsing the {} hash algorithm".format(hash_algorithm.__name__))
    with open(file_name, 'rb') as fo:
        content = fo.read()
        start = datetime.datetime.now()
        hash_value = hash_algorithm(content).hexdigest()
        diff = datetime.datetime.now() - start
        print("{0:.15f}".format(float(diff.microseconds / float(file_size))))
        print("Time taken per byte in Seconds: {0:.15f}".format(float(diff.total_seconds() / (file_size))))
        print("Time taken in seconds to find Hash: {}".format(diff.total_seconds()))
        print("Hash value is : {}\n".format(hash_value))


def question_1e_1f(file_name, output_file_name, key_length):
    """
    This section deals with RSA encryption using PCKS#1 OAEP
    :param file_name: Input file name
    :param output_file_name: Output file name
    :param key_length: Length of key in bits
    """
    print("\nUsing the {} RSA algorithm".format(key_length))
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.PublicKey import RSA
    fo_input = open(file_name, 'rb')
    fo = open(output_file_name, 'wb')
    key_gen_start = datetime.datetime.now()
    key = RSA.generate(key_length)
    print("time taken for Keygen of size {} in Seconds is {}".format(key_length, (
            datetime.datetime.now() - key_gen_start).total_seconds()))
    print(key.publickey())
    cipher = PKCS1_OAEP.new(key.publickey())
    encr_start_time = datetime.datetime.now()
    while True:
        chunked_data = fo_input.read(190)
        if chunked_data:
            ct = cipher.encrypt(chunked_data)
            fo.write(ct)
        else:
            break
    encr_time = datetime.datetime.now() - encr_start_time
    print("time taken for Encryption in Seconds is {}".format(encr_time))
    print("Time taken in seconds per byte for encryption is {}".format(
        encr_time.total_seconds() / os.path.getsize(file_name)))
    fo_input.close()
    fo.close()

    fo_encr = open(output_file_name, 'rb')
    fo_output = open(file_name + "decrypted", 'wb')
    decipher = PKCS1_OAEP.new(key)
    decr_start_time = datetime.datetime.now()
    while True:
        chunked_data = fo_encr.read(key_length / 8)
        if chunked_data:
            pt = decipher.decrypt(chunked_data)
            fo_output.write(pt)
        else:
            break
    decry_time = datetime.datetime.now() - decr_start_time
    print("time taken for Decryption in Seconds is {}".format(decry_time))
    print("Time taken in seconds per byte for decryption is {}".format(
        decry_time.total_seconds() / os.path.getsize(file_name)))
    fo_output.close()
    fo_encr.close()

    fo_final = open(file_name, 'rb')
    plaintext = fo_final.read()
    fo_final.close()
    fo_final = open(file_name + "decrypted", 'rb')
    decrypted_text = fo_final.read()
    fo_final.close()
    print(
    "The bool value for equality of plaintext and decrypted ciphertext is : {}\n".format(plaintext == decrypted_text))


def question_1g_1h(file_name, output_file_name, key_length):
    """
    This section deals with the signature and verification of the file
    :param file_name: Input file name
    :param output_file_name: Output file name
    :param key_length: Length of the key in bits
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.backends import default_backend

    print("Starting Signature and Verification for {} bit key length".format(key_length))
    key_start_time = datetime.datetime.now()
    key = dsa.generate_private_key(key_size=key_length, backend=default_backend())
    print("Time taken for KeyGen in Seconds is {}".format((datetime.datetime.now() - key_start_time).total_seconds()))
    fo_input = open(file_name, 'rb')
    content = fo_input.read()
    fo_input.close()

    # Signature
    signing_start_time = datetime.datetime.now()
    # signer = DSS.new(key, 'fips-186-3')
    h = hashes.SHA256()
    signature = key.sign(content, h)
    fo = open(output_file_name, 'wb')
    fo.write(signature)
    fo.close()
    diff = datetime.datetime.now() - signing_start_time
    print("Time taken in seconds for Signing this document was {}".format(diff.total_seconds()))
    print("Time taken in seconds per byte for signing this document was {0:.7f}".format(
        diff.total_seconds() / float(os.path.getsize(file_name))))

    # Verification
    verify_start_time = datetime.datetime.now()
    fo = open(output_file_name, 'rb')
    sig_content = fo.read()
    fo.close()

    try:
        key.public_key().verify(signature, content, hashes.SHA256())
        diff_verify = datetime.datetime.now() - verify_start_time
        print("Time taken for Verifying this document was {}".format(diff_verify.total_seconds()))
        print("Time taken in microseconds per byte for verifying this document was {0:.5f}".format(
            float((diff_verify.total_seconds()) / os.path.getsize(output_file_name))))
        print("Valid Signature!!\n")
    except:
        print("Invalid Signature!.. Corrupted!!\n")


if __name__ == '__main__':
    print("1MB")
    question_1a_1b_1c("1MB.txt", "1MBfileCTR256.enc", "CTR", 32, os.path.getsize("1MB.txt"))
    question_1a_1b_1c("1MB.txt", "1MBfileCTR128.enc", "CTR", 16, os.path.getsize("1MB.txt"))
    question_1a_1b_1c("1MB.txt", "1MBfileCBC128.enc", "CBC", 16, os.path.getsize("1MB.txt"))

    print("\n\n")
    print("1KB")
    question_1a_1b_1c("1KB.txt", "1KBfileCTR256.enc", "CTR", 32, os.path.getsize("1KB.txt"))
    question_1a_1b_1c("1KB.txt", "1KBfileCTR128.enc", "CTR", 16, os.path.getsize("1KB.txt"))
    question_1a_1b_1c("1KB.txt", "1KBfileCBC128.enc", "CBC", 16, os.path.getsize("1KB.txt"))

    import hashlib
    import sha3

    question_1d("1KB.txt", hashlib.sha256, os.path.getsize("1KB.txt"))
    question_1d("1MB.txt", hashlib.sha256, os.path.getsize("1MB.txt"))
    question_1d("1KB.txt", hashlib.sha512, os.path.getsize("1KB.txt"))
    question_1d("1MB.txt", hashlib.sha512, os.path.getsize("1MB.txt"))
    question_1d("1KB.txt", sha3.sha3_256, os.path.getsize("1KB.txt"))
    question_1d("1MB.txt", sha3.sha3_256, os.path.getsize("1MB.txt"))

    question_1e_1f("1KB.txt", "1KBfileRSA2048.enc", 2048)
    question_1e_1f("1MB.txt", "1MBfileRSA2048.enc", 2048)
    question_1e_1f("1KB.txt", "1KBfileRSA3072.enc", 3072)
    question_1e_1f("1MB.txt", "1MBfileRSA3072.enc", 3072)

    question_1g_1h("1KB.txt", "1KBfileDSA2048.enc", 2048)
    question_1g_1h("1MB.txt", "1MBfileDSA2048.enc", 2048)
    question_1g_1h("1KB.txt", "1KBfileDSA3072.enc", 3072)
    question_1g_1h("1MB.txt", "1MBfileDSA3072.enc", 3072)
