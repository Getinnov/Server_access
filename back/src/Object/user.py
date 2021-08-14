from cryptography.hazmat.primitives import hashes
from phrase import Phrase
import random

try:
    from .rethink import get_conn, r
except:
    pass

class user:
    def __init__(self, id = -1):
        if id is None:
            id = -1
        self.id = str(id)
        try:
            self.red = get_conn().db("auth").table('users')
        except:
            self.red = None
        self.model = {
            "id": None,
            "passphrase_verify": {
                "main": None,
                "verified": None
            },
            "password_verify": {
                "main": None,
            }
        }

    def connect(self, id, password):
        if not self.__exit(id):
            return self.register(id, password)



    def register(self, id, password):
        if self.__exit(id):
            if self.__verified(id):
                return self.connect(id, password)
            self.red.get(id).delete().run()
        phrase = Phrase.create(16)
        data = self.model
        data["id"] = str(id)
        data["password_verify"]["main"] = Phrase.encode(str(password))[1]
        data["passphrase_verify"]["verified"] = False
        data["passphrase_verify"]["main"] = Phrase.encode(phrase)[1]
        phrase_scramble = phrase.split(' ')
        random.shuffle(phrase_scramble)
        self.red.insert([data]).run()
        ret = {
            "phrase": phrase,
            "scramble": phrase_scramble,
        }
        return [True, ret, None]

    def passphrase_verify(self, passphrase):
        data = dict(self.red.get(self.id).run())
        if Phrase.encode(str(phrase))[1]

    def __exist(self, id):
        res = list(self.red.filter(r.row["id"] == id).run())
        if len(res) > 0:
            return True
        return False

    def __verified(self, id):
        res = list(self.red.filter(r.row["id"] == id).run())
        if len(res) > 0:
            return res[0]['passphrase_verify']['verified']
        return False
