from hashlib import sha512
from random import randrange

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

    @classmethod
    def addPoint(cls, point1, point2):
        """

        :param point1:
        :param point2:
        :return:
        """

        if point1 == (0, 0):  # 0 + point2 = point2
            return point2
        if point2 == (0, 0):  # point1 + 0 = point1
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2:
            if y1 != y2: return (0, 0)
            #
            l = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
        else:
            #
            l = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

        x = (l ** 2 - x1 - x2) % curve.p
        y = -(l * (x - x1) + y1) % curve.p

        return (x, y)

    @classmethod
    def multiplyPoint(cls, k, point):
        """
        
        :param k: 
        :param point: 
        :return: 
        """

        if k < 0:  # k * point = -k * (-point)
            return cls.multiplyPoint(-k, (-point[0], - point[1]))

        tempPoint = point
        result = (0, 0)

        while k:
            if k % 2 != 0:
                result = cls.addPoint(result, tempPoint)
            tempPoint = cls.addPoint(tempPoint, tempPoint)
            k //= 2

        return result

    def getPointX(self, k):
        return self.multiplyPoint(k, self.g)


def hash_message(message):
    """

    :param message: message line
    :return: truncated SHA521 hash of the message
    """

    bin_hash = sha512(message.encode("utf-8")).digest()
    dec_hash = int.from_bytes(bin_hash, 'big')

    return dec_hash >> (dec_hash.bit_length() - curve.q.bit_length())


def inverse_mod(k, p):
    """

    :param k:
    :param p:
    :return: the integer x such that (x * k) % p == 1.
    """
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

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


class Digital_signature():
    """
    ...
    """

    @property
    def message_hash(self):
        return self._message_hash

    @message_hash.setter
    def message_hash(self, message_hash):
        self._message_hash = message_hash

    def form(self, d):
        """

        :param d:
        :return:
        """
        a = self.message_hash
        e = a % curve.q
        if e == 0: e = 1

        r, k = 0, 0
        while r == 0:
            # k = randrange(1, curve.q - 1)
            k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
            x, y = curve.getPointX(k)
            r = x % curve.q
        s = (r * d + k * e) % curve.q

        return (r, s)

    def check(self, public_key, signature):
        """

        :param public_key:
        :param signature:
        :return:
        """
        valid = '\tSuccessful signature verification'
        invalid = '\tInvalid signature verification'
        a = self.message_hash

        r, s = signature
        if not (0 < r < curve.q and 0 < s < curve.q):
            return invalid

        e = a % curve.q
        if e == 0: e = 1

        v = inverse_mod(e, curve.q)

        z1 = (s * v) % curve.q
        z2 = (-r * v) % curve.q

        x, y = curve.addPoint(
            curve.multiplyPoint(z1, curve.g),
            curve.multiplyPoint(z2, public_key)
        )

        R = x % curve.q

        return valid if R == r else invalid

curve = EllipticCurve(
    name="example1",
    a=7,
    b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
    p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
    q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
    m=57896044618658097711785492504343953927082934583725450622380973592137631069619,
    Gx=2,
    Gy=4018974056539037503335449422937059775635739389905545080690979365213431566280
)

# curve = EllipticCurve(
#     name="example2",
#     a=7,
#     b=43308876546767276905765904595650931995942111794451039583252968842033849580414,
#     p=57896044618658097711785492504343953926634992332820282019728792003956564821041,
#     q=57896044618658097711785492504343953927082934583725450622380973592137631069619,
#     m=57896044618658097711785492504343953927082934583725450622380973592137631069619,
#     Gx=2,
#     Gy=4018974056539037503335449422937059775635739389905545080690979365213431566280
# )


def main():
    wide = 100
    choice = None
    while choice != 0:
        print("-" * wide)
        choice = int(input(
            "\tChoose operation:\n"
            "\t\t1 - form new digital signature\n"
            "\t\t2 - check digital signature\n"
            "\t\t3 - hash message\n"
            "\t\t0 - exit\n"
        ))
        print("-" * wide)

        signature = Digital_signature()

        if choice == 1:
            private_key = 55441196065363246126355624130324183196576709222340016572108097750006097525544
            hashed_message = 20798893674476452017134061561508270130637142515379653289952617252661468872421

            # private_key = int(input('\tEnter a private key (d): '))
            # hashed_message = int(input('\tEnter a message hash (alpha): '))

            signature.message_hash = hashed_message
            sign = signature.form(private_key)  # M d -> dzeta
            print("-" * wide, f'\n\tSignature in 10: {sign}\n', sep='\n')

        elif choice == 2:
            public_key = (
                57520216126176808443631405023338071176630104906313632182896741342206604859403,
                17614944419213781543809391949654080031942662045363639260709847859438286763994
            )
            sign = (
                29700980915817952874371204983938256990422752107994319651632687982059210933395,
                574973400270084654178925310019147038455227042649098563933718999175515839552
            )
            hashed_message = 20798893674476452017134061561508270130637142515379653289952617252661468872421

            # public_key = (
            #     int(input('\tEnter the 1st part of public key (Qx): ')),
            #     int(input('\tEnter the 2nd part of public key (Qy): '))
            # )
            # sign = (
            #     int(input('\tEnter the 1st part of signature (r): ')),
            #     int(input('\tEnter the 2nd part of signature (s): '))
            # )
            # hashed_message = int(input('\tEnter a message hash (alpha): '))

            signature.message_hash = hashed_message
            print("-" * wide, signature.check(public_key, sign), sep='\n')

        elif choice == 3:
            message = input('\tEnter a message: ')
            hashed_message = hash_message(message)
            print(f"\tMessage hash: {hashed_message}")


if __name__ == '__main__':
    main()
