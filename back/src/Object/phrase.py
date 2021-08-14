import random
from cryptography.hazmat.primitives import hashes

class Phrase:
    def create(words: int = 12):
        """
        open dic and create a n unique words phrase
        """
        with open('../Ressources/dico.txt') as f:
            content = f.readlines()
        phrase = []
        total = len(content)
        for _ in range(words):
            n = random.randint(0, total)
            word  = content[n][:-1]
            if word not in phrase:
                phrase.append(word)
        return ' '.join(phrase)

    def encode(passphrase:str) -> str:
        """
        encode a string 2 time using sha256 and return
        """
        hash = hashes.Hash(hashes.SHA256())
        hash.update(passphrase.encode('utf-8'))
        hash = hash.finalize().hex()
        verify = hashes.Hash(hashes.SHA256())
        verify.update(hash.encode('utf-8'))
        verify = verify.finalize().hex()
        return hash, verify

if __name__ == '__main__':
    print(f"{Phrase.create()}")
    print(Phrase.encode('testt'))
