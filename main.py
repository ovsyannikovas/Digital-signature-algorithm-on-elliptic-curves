from hashlib import sha512
from random import randrange


class EllipticCurve:
    """
     y^2 = x^3 + a * x + b (mod p)
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
        An algorithm for adding one point of an elliptic curve to another point.

        :param point1: first point tuple (x, y)
        :param point2: second point tuple (x, y)
        :return: (x, y) of point = point1 + point2 by rules
        """

        # 0 + point2 = point2
        if point1 == (0, 0):
            return point2
        # point1 + 0 = point1
        if point2 == (0, 0):
            return point1

        x1, y1 = point1
        x2, y2 = point2

        if x1 == x2:
            if y1 != y2: return (0, 0)
            # l = (3x1^2 + a)/(2y1) (mod p) = (3x1^2 + a) * 2y1 (inverse_mod p)
            l = (3 * x1 ** 2 + curve.a) * inverse_mod(2 * y1, curve.p)
        else:
            # l = (y2 - y1)/(x2 - x1) (mod p) = (y2 - y1) * (x2 - x1) (inverse_mod p)
            l = (y2 - y1) * inverse_mod(x2 - x1, curve.p)

        x = (l ** 2 - x1 - x2) % curve.p
        y = (l * (x1 - x) - y1) % curve.p

        return (x, y)

    @classmethod
    def multiplyPoint(cls, k, point):
        """
        An algorithm for multiplying an elliptic point by a scalar.

        :param k: multiplicity/scalar of a point
        :param point: point tuple (x, y)
        :return: (Cx, Cy) of point C = kG
        """

        # k * point = -k * (-point)
        if k < 0:
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
        return self.multiplyPoint(k, self.g)[0]


def hash_message(message):
    """
    The algorithm for hashing a message with the SHA512 hash function modulo p.

    :param message: message line
    :return: truncated SHA521 hash of the message
    """

    bin_hash = sha512(message.encode("utf-8")).digest()
    dec_hash = int.from_bytes(bin_hash, 'big')

    return dec_hash >> (dec_hash.bit_length() - curve.q.bit_length())


def inverse_mod(k, p):
    """
    The inverse of k modulo p.
        (x * k) % p == 1

    :param k: k
    :param p: the module
    :return: the integer x such that (x * k) % p == 1.
    """

    # k ** -1 = p - (-k) ** -1  (mod p)
    if k < 0:
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

    @property
    def message_hash(self):
        return self._message_hash

    @message_hash.setter
    def message_hash(self, message_hash):
        self._message_hash = message_hash

    def form(self, d):
        """
        An algorithm that generates a digital signature.

        :param d: private key
        :return: a signature tuple (r, s)
        """

        e = self.message_hash % curve.q
        if e == 0: e = 1

        r, k = 0, 0
        while r == 0:
            if example == 1:
                k = 53854137677348463731403841147996619241504003434302020712960838528893196233395
            elif example == 2:
                k = 175516356025850499540628279921125280333451031747737791650208144243182057075034446102986750962508909227235866126872473516807810541747529710309879958632945
            else:
                k = randrange(1, curve.q - 1)
            x = curve.getPointX(k)
            r = x % curve.q
        s = (r * d + k * e) % curve.q

        return (r, s)

    def check(self, public_key, signature):
        """
        An algorithm that verifies a digital signature.

        :param public_key: public key tuple (Qx, Qy)
        :param signature: a signature tuple (r, s)
        :return:
        """
        valid = '\tSuccessful signature verification'
        invalid = '\tInvalid signature verification'

        r, s = signature
        if not (0 < r < curve.q and 0 < s < curve.q):
            return invalid

        e = self.message_hash % curve.q
        if e == 0: e = 1

        # v = e^(-1) (mod q) = e (inverse_mod q)
        v = inverse_mod(e, curve.q)

        z1 = (s * v) % curve.q
        z2 = (-r * v) % curve.q

        x, y = curve.addPoint(
            curve.multiplyPoint(z1, curve.g),
            curve.multiplyPoint(z2, public_key)
        )

        R = x % curve.q

        return valid if R == r else invalid


def main():
    wide = 100
    choice = None
    while choice != 0:
        print("-" * wide)
        choice = int(input(
            "\t* Data is entered and output in decimal notation.\n\n"
            "\tChoose operation:\n"
            "\t\t1 - form new digital signature\n"
            "\t\t2 - check digital signature\n"
            "\t\t3 - hash message\n"
            "\t\t0 - exit\n"
        ))
        print("-" * wide)

        signature = Digital_signature()

        if choice == 1:
            if example == 1:
                private_key = 55441196065363246126355624130324183196576709222340016572108097750006097525544
                hashed_message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
            elif example == 2:
                private_key = 610081804136373098219538153239847583006845519069531562982388135354890606301782255383608393423372379057665527595116827307025046458837440766121180466875860
                hashed_message = 2897963881682868575562827278553865049173745197871825199562947419041388950970536661109553499954248733088719748844538964641281654463513296973827706272045964
            else:
                private_key = int(input('\tEnter a private key (d): '))
                hashed_message = int(input('\tEnter a message hash (alpha): '))
                print("-" * wide)

            signature.message_hash = hashed_message
            sign = signature.form(private_key)
            print(f'\tSignature: \n'
                  f'\t({sign[0]},\n'
                  f'\t{sign[1]})', sep='\n')

        elif choice == 2:
            if example == 1:
                public_key = (
                    57520216126176808443631405023338071176630104906313632182896741342206604859403,
                    17614944419213781543809391949654080031942662045363639260709847859438286763994
                )
                sign = (
                    29700980915817952874371204983938256990422752107994319651632687982059210933395,
                    574973400270084654178925310019147038455227042649098563933718999175515839552
                )
                hashed_message = 20798893674476452017134061561508270130637142515379653289952617252661468872421
            elif example == 2:
                public_key = (
                    909546853002536596556690768669830310006929272546556281596372965370312498563182320436892870052842808608262832456858223580713780290717986855863433431150561,
                    2921457203374425620632449734248415455640700823559488705164895837509539134297327397380287741428246088626609329139441895016863758984106326600572476822372076
                )
                sign = (
                    2489204477031349265072864643032147753667451319282131444027498637357611092810221795101871412928823716805959828708330284243653453085322004442442534151761462,
                    864523221707669519038849297382936917075023735848431579919598799313385180564748877195639672460179421760770893278030956807690115822709903853682831835159370
                )
                hashed_message = 2897963881682868575562827278553865049173745197871825199562947419041388950970536661109553499954248733088719748844538964641281654463513296973827706272045964
            else:
                public_key = (
                    int(input('\tEnter the 1st part of public key (Qx): ')),
                    int(input('\tEnter the 2nd part of public key (Qy): '))
                )
                sign = (
                    int(input('\tEnter the 1st part of signature (r): ')),
                    int(input('\tEnter the 2nd part of signature (s): '))
                )
                hashed_message = int(input('\tEnter a message hash (alpha): '))
                print("-" * wide)

            signature.message_hash = hashed_message
            print(signature.check(public_key, sign), sep='\n')

        elif choice == 3:
            message = input('\tEnter a message: ')
            hashed_message = hash_message(message)
            print(f"\tMessage hash modulo p: {hashed_message}")


if __name__ == '__main__':
    # choosing program mode
    example = 2

    if example == 1:
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
    else:
        curve = EllipticCurve(
            name="example2",
            a=7,
            b=1518655069210828534508950034714043154928747527740206436194018823352809982443793732829756914785974674866041605397883677596626326413990136959047435811826396,
            p=3623986102229003635907788753683874306021320925534678605086546150450856166624002482588482022271496854025090823603058735163734263822371964987228582907372403,
            q=3623986102229003635907788753683874306021320925534678605086546150450856166623969164898305032863068499961404079437936585455865192212970734808812618120619743,
            m=3623986102229003635907788753683874306021320925534678605086546150450856166623969164898305032863068499961404079437936585455865192212970734808812618120619743,
            Gx=1928356944067022849399309401243137598997786635459507974357075491307766592685835441065557681003184874819658004903212332884252335830250729527632383493573274,
            Gy=2288728693371972859970012155529478416353562327329506180314497425931102860301572814141997072271708807066593850650334152381857347798885864807605098724013854
        )

    main()
