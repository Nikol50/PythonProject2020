from Crypto.Cipher import AES
from Crypto import Random

class symmetric:

    def generating_key_and_iv(self):
        key = Random.new().read(AES.block_size)
        iv = Random.new().read(AES.block_size)
        return key, iv

    def read_file(self, file_name):
        try:
            input_file = open(file_name, 'rb')
            input_data = input_file.read()
            input_file.close()
            return input_data
        except:
            return False

    def encrypt_file(self, key, iv, input_data):
        try:
            cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
            enc_data = cfb_cipher.encrypt(input_data)
            #enc_file = open("encrypted.enc", "wb")
            #enc_file.write(enc_data)
            #enc_file.close()
            return enc_data
        except:
            return False

    def decrypt_file(self, key, iv, enc_data):
        #enc_file2 = open("encrypted.enc", 'rb')
        #enc_data2 = enc_file2.read()
        #enc_file2.close()
        cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
        plain_data = cfb_decipher.decrypt(enc_data)
        return plain_data

    def output_file(self, plain_data, output_file):
        output_file = open(output_file, "wb")
        output_file.write(plain_data)
        output_file.close()





