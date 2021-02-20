import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


class PGP:
    @staticmethod
    def generate_key_pair(name):
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new(name)
        key.add_uid(uid,
                    usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA512],
                    ciphers=[PubKeyAlgorithm.RSAEncryptOrSign, SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP,
                                 CompressionAlgorithm.Uncompressed])
        # public key is saved in public.txt
        # private key is saved in private.txt
        open("public.txt", "w").write(str(key.pubkey))
        open("private.txt", "w").write(str(key))

    @staticmethod
    def encrypt(data):
        public_key, _ = pgpy.PGPKey.from_file("public.txt")
        # pubkey = public key
        encrypted_data = public_key.pubkey.encrypt(pgpy.PGPMessage.new(data), cipher=SymmetricKeyAlgorithm.AES256)
        f = open("encrypted.txt", "w")
        f.write(str(encrypted_data))
        f.close()

        return bytes(encrypted_data)

    @staticmethod
    def decrypt(data):
        private_key, _ = pgpy.PGPKey.from_file("private.txt")
        decrypted_data = private_key.decrypt(pgpy.PGPMessage.from_blob(data))
        return bytes(decrypted_data._message.contents) if isinstance(decrypted_data._message.contents,
                                                                     bytearray) else decrypted_data._message.contents


PGP.generate_key_pair("")

enc = PGP.encrypt(open("plain_input.txt", "r").read())
print("Finished encrypting...")

dec = PGP.decrypt(open("encrypted.txt", "r").read())
print("Finished decrypting...")

open("decrypted.txt", "w").write(dec)
