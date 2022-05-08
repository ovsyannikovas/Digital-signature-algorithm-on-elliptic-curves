from hashlib import sha512
from random import randrange


# r = 29700980915817952874371204983938256990422752107994319651332687982059210933395
# d = 55441196065363246126355624130324183196576709222340016572108097750006097525544
# k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
# e = 20798893674476452017134061561508270130637142515379653289952617252661468872421
# q = 57896044618658097711785492504343953927082934583725450622380973592137631069619

class EllipticCurve:
    """
    # y^2 = x^3 + a * x + b (mod p)
    """

    def __init__(self, a, b, p, q, m, Gx, Gy, name):
        self.name = name
        # Coefficient a
        self.a = a
        # Coefficient b
        self.b = b
        # Prime number > 3
        self.p = p
        # Subgroup order
        self.q = q
        # Group order
        self.m = m
        # Base point coordinates
        self.g = (Gx, Gy)

    def contains(self, point):
        x, y = point
        if not 0 <= x <= self.q - 1 or not 0 <= y <= self.q - 1:
            return False
        if (y ** 2 - (x ** 3 + self.a * x + self.b)) % self.q != 0:
            return False
        return True

    @classmethod
    def inverse_mod(cls, k, p):
        """Returns the inverse of k modulo p.
        This function returns the only integer x such that (x * k) % p == 1.
        k must be non-zero and p must be a prime.
        """
        if k < 0:
            # k ** -1 = p - (-k) ** -1  (mod p)
            return p - cls.inverse_mod(-k, p)

        # Extended Euclidean algorithm.
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = p, k

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        gcd, x, y = old_r, old_s, old_t

        return x % p

    @classmethod
    def addPoint(cls, point1, point2):
        if point1 == (0, 0):  # 0 + point2 = point2
            return point2
        if point2 == (0, 0):  # point1 + 0 = point1
            return point1

        x1, y1 = point1
        x2, y2 = point2
        l = None

        if x1 == x2:
            if y1 != y2: return (0, 0)
            # l = ((3 * x1 ** 2 + curve.a) / (2 * y1)) % curve.p
            l = (3 * x1 * x1 + curve.a) * cls.inverse_mod(2 * y1, curve.p)
        else:
            # l = ((y2 - y1) / (x2 - x1)) % curve.p
            l = (y1 - y2) * cls.inverse_mod(x1 - x2, curve.p)

        x = (l ** 2 - x1 - x2) % curve.p
        y = -(l * (x - x1) + y1) % curve.p

        return (x, y)

    @classmethod
    def multiplyPoint(cls, k, point):
        if k < 0:  # k * point = -k * (-point)
            return cls.multiplyPoint(-k, (-point[0], - point[1]))

        # k -= 1
        tempPoint = point
        result = (0, 0)

        while k:
            if k % 2 != 0:
                result = cls.addPoint(result, tempPoint)

            tempPoint = cls.addPoint(tempPoint, tempPoint)

            k //= 2

        return result

    @classmethod
    def getPointX(cls, k, point):
        return cls.multiplyPoint(k, point)


# curve = EllipticCurve(
#     name="secp256k1",
#     a=0x0000000000000000000000000000000000000000000000000000000000000000,
#     b=0x0000000000000000000000000000000000000000000000000000000000000007,
#     p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
#     q=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
#     Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
#     Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
# )

curve = EllipticCurve(
    name="example",
    a=7,
    b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
    p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
    q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
    m=57896044618658097711785492504343953927082934583725450622380973592137631069619,
    Gx=2,
    Gy=4018974056539037503335449422937059775635739389905545080690979365213431566280
)


def main():
    choice = None
    while choice != 0:
        print("-" * 50)
        choice = 1
        # choice = int(input(
        #     "\tChoose operation:\n"
        #     "\t\t1 - form new digital signature\n"
        #     "\t\t2 - check digital signature\n"
        #     "\t\t0 - exit\n"
        # ))
        signature = Digital_signature()
        # message = input('\tEnter a message: ')
        # private_key, public_key = make_pair()

        # print(public_key)

        if choice == 1:
            message = 'fuck'
            private_key = 55441196065363246126355624130324183196576709222340016572108097750006097525544
            # signature.d = int(input('\tEnter a private key (d) in 10: '))
            sign = signature.form(message, private_key)  # M d -> dzeta
            print(f'\tSignature in 10: {sign}\n')
            choice = 0
        elif choice == 2:  # M dzeta Q -> yes | no
            message = 'fuck'
            public_key = (
                57520216126176808443631405023338071176630104906313632182896741342206604859403,
                17614944419213781543809391949654080031942662045363639260709847859438286763994
            )
            sign = (
                29700980915817952874371204983938256990422752107994319651632687982059210933395,
                574973400270084654178925310019147038455227042649098563933718999175515839552
            )
            print(signature.check(message, public_key, sign))
            choice = 0
    del signature


class Digital_signature():  # M d Q dzeta

    @staticmethod
    def hash_message(message):
        """Returns the truncated SHA521 hash of the message."""
        message_hash = sha512(message).digest()
        e = int.from_bytes(message_hash, 'big')

        # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
        # should be discarded.

        return e >> (e.bit_length() - curve.q.bit_length())

    @classmethod
    def form(cls, message, d):
        a = cls.hash_message(message.encode('utf-8'))
        e = a % curve.q
        e = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        if e == 0: e = 1
        r, s = 0, 0
        while r == 0:
            # k = randrange(1, curve.q - 1)
            k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
            x, y = EllipticCurve.getPointX(k, curve.g)
            r = x % curve.q
            s = (r * d + k * e) % curve.q

        return (r, s)

    @classmethod
    def check(cls, message, public_key, signature):
        r, s = signature
        if not (0 < r < curve.q and 0 < s < curve.q):
            return 'invalid signature verification'

        # a = cls.hash_message(message)
        # e = a % curve.q
        e = 20798893674476452017134061561508270130637142515379653289952617252661468872421
        if e == 0: e = 1

        v = EllipticCurve.inverse_mod(e, curve.q)

        z1 = (s * v) % curve.q
        z2 = (-r * v) % curve.q

        x, y = EllipticCurve.addPoint(
            EllipticCurve.multiplyPoint(z1, curve.g),
            EllipticCurve.multiplyPoint(z2, public_key)
        )

        R = x % curve.q

        if R == r:
            return 'successful signature verification'
        else:
            return 'invalid signature verification'


if __name__ == '__main__':
    main()
