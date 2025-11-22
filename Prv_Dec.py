import time
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class EllipticCurveElGamalWithProof:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
        self.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

        self.g = self._get_generator()

    def _mod_inverse(self, a: int, m: int) -> int:
        return pow(a, m - 2, m)

    def _get_generator(self):
        g_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        g_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        return ec.EllipticCurvePublicNumbers(g_x, g_y, self.curve).public_key(self.backend)

    def _point_multiply(self, point, scalar: int):
        if scalar == 0 or point is None:
            return None

        if scalar < 0:
            scalar = scalar % self.order
            if scalar == 0:
                return None

        result = None
        current = point
        k = scalar

        while k > 0:
            if k & 1:
                result = self._point_add(result, current)
            current = self._point_add(current, current)
            k >>= 1

        return result

    def _point_add(self, point1, point2):
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        nums1 = point1.public_numbers()
        nums2 = point2.public_numbers()
        x1, y1 = nums1.x, nums1.y
        x2, y2 = nums2.x, nums2.y

        if x1 == x2:
            if y1 == y2:
                if y1 == 0:
                    return None
                s_numerator = (3 * x1 * x1 + self.a) % self.p
                s_denominator = (2 * y1) % self.p
                s_denominator_inv = self._mod_inverse(s_denominator, self.p)
                s = (s_numerator * s_denominator_inv) % self.p
            else:
                return None
        else:
            s_numerator = (y2 - y1) % self.p
            s_denominator = (x2 - x1) % self.p
            s_denominator_inv = self._mod_inverse(s_denominator, self.p)
            s = (s_numerator * s_denominator_inv) % self.p

        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        try:
            return ec.EllipticCurvePublicNumbers(x3, y3, self.curve).public_key(self.backend)
        except Exception:
            return None

    def _point_negate(self, point):
        if point is None:
            return None

        nums = point.public_numbers()
        neg_y = (-nums.y) % self.p
        return ec.EllipticCurvePublicNumbers(nums.x, neg_y, self.curve).public_key(self.backend)

    def _point_to_int(self, point):
        if point is None:
            return 0
        nums = point.public_numbers()
        return (nums.x << 256) | nums.y

    def key_generation(self):
        start_time = time.time()

        x = secrets.randbelow(self.order - 1) + 1

        h = self._point_multiply(self.g, x)

        keygen_time = time.time() - start_time

        return (x, h), keygen_time

    def encrypt(self, h, message_point):
        start_time = time.time()

        r = secrets.randbelow(self.order - 1) + 1

        c1 = self._point_multiply(self.g, r)

        h_r = self._point_multiply(h, r)

        c2 = self._point_add(message_point, h_r)

        encrypt_time = time.time() - start_time

        return (c1, c2), encrypt_time

    def decrypt(self, x, ciphertext):
        start_time = time.time()

        c1, c2 = ciphertext

        s = self._point_multiply(c1, x)

        neg_s = self._point_negate(s)

        message_point = self._point_add(c2, neg_s)

        decrypt_time = time.time() - start_time

        return message_point, decrypt_time

    def generate_proof(self, x, message_point, ciphertext):
        start_time = time.time()

        c1, c2 = ciphertext

        a = secrets.randbelow(self.order - 1) + 1
        A = self._point_multiply(self.g, a)

        neg_message = self._point_negate(message_point)
        c2_minus_m = self._point_add(c2, neg_message)

        B = self._point_multiply(c2_minus_m, a)

        h_pub = self._point_multiply(self.g, x)
        g_int = self._point_to_int(self.g)
        h_int = self._point_to_int(h_pub)
        m_int = self._point_to_int(message_point)
        c1_int = self._point_to_int(c1)
        c2_int = self._point_to_int(c2)
        A_int = self._point_to_int(A)
        B_int = self._point_to_int(B)

        hash_input = f"{g_int}{h_int}{m_int}{c1_int}{c2_int}{A_int}{B_int}".encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(hash_input)
        e_hash = digest.finalize()
        e = int.from_bytes(e_hash, 'big') % self.order

        z = (x * e + a) % self.order

        proof = (message_point, A, B, z)

        proof_time = time.time() - start_time

        return proof, proof_time

    def verify_proof(self, h, ciphertext, proof):
        start_time = time.time()

        c1, c2 = ciphertext
        m, A, B, z = proof

        g_int = self._point_to_int(self.g)
        h_int = self._point_to_int(h)
        m_int = self._point_to_int(m)
        c1_int = self._point_to_int(c1)
        c2_int = self._point_to_int(c2)
        A_int = self._point_to_int(A)
        B_int = self._point_to_int(B)

        hash_input = f"{g_int}{h_int}{m_int}{c1_int}{c2_int}{A_int}{B_int}".encode()
        digest = hashes.Hash(hashes.SHA256())
        digest.update(hash_input)
        e_hash = digest.finalize()
        e = int.from_bytes(e_hash, 'big') % self.order

        g_z = self._point_multiply(self.g, z)
        h_e = self._point_multiply(h, e)
        h_e_plus_A = self._point_add(h_e, A)

        verification_time = time.time() - start_time

        is_valid = self._points_equal(g_z, h_e_plus_A)

        return is_valid, verification_time

    def _points_equal(self, point1, point2):
        if point1 is None and point2 is None:
            return True
        if point1 is None or point2 is None:
            return False

        try:
            nums1 = point1.public_numbers()
            nums2 = point2.public_numbers()
            return nums1.x == nums2.x and nums1.y == nums2.y
        except Exception:
            return False

    def create_test_message(self):
        msg_scalar = secrets.randbelow(1000) + 1
        message_point = self._point_multiply(self.g, msg_scalar)
        return message_point

    def benchmark_operations(self):
        print("NIST P-256椭圆曲线ElGamal操作时间基准测试")
        print("=" * 50)

        (private_key, public_key), keygen_time = self.key_generation()
        print(f"密钥生成时间: {keygen_time * 1000:.4f} 毫秒")

        message = self.create_test_message()

        ciphertext, encrypt_time = self.encrypt(public_key, message)
        print(f"加密时间: {encrypt_time * 1000:.4f} 毫秒")

        decrypted_message, decrypt_time = self.decrypt(private_key, ciphertext)
        print(f"解密时间: {decrypt_time * 1000:.4f} 毫秒")

        proof, proof_gen_time = self.generate_proof(private_key, message, ciphertext)
        print(f"证明生成时间: {proof_gen_time * 1000:.4f} 毫秒")

        is_valid, proof_verify_time = self.verify_proof(public_key, ciphertext, proof)
        print(f"证明验证时间: {proof_verify_time * 1000:.4f} 毫秒")
        print(f"证明验证结果: {'有效' if is_valid else '无效'}")

        print("\n" + "=" * 50)
        print("性能总结")
        print("=" * 50)
        total_time = keygen_time + encrypt_time + decrypt_time + proof_gen_time + proof_verify_time
        proof_system_time = proof_gen_time + proof_verify_time
        print(f"总时间: {total_time * 1000:.4f} 毫秒")
        print(f"证明系统开销: {proof_system_time * 1000:.4f} 毫秒")
        print(f"证明系统占比: {proof_system_time / total_time * 100:.2f}%")

        return {
            'keygen_time': keygen_time,
            'encrypt_time': encrypt_time,
            'decrypt_time': decrypt_time,
            'proof_gen_time': proof_gen_time,
            'proof_verify_time': proof_verify_time,
            'total_time': total_time,
            'proof_system_time': proof_system_time
        }


def main():
    elgamal = EllipticCurveElGamalWithProof()

    results = elgamal.benchmark_operations()


if __name__ == "__main__":
    main()