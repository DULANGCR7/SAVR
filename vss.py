import time
from typing import List, Tuple
import secrets
import hashlib


class StandardPedersenVSS:
    def __init__(self, n: int = 100, t: int = 50):
        self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
        self.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self.Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        self.Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

        self.n = n
        self.t = t

        self.Hx, self.Hy = self._generate_H_point()

    def _mod_inverse(self, a: int, m: int) -> int:
        return pow(a, m - 2, m)

    def _point_add(self, x1: int, y1: int, x2: int, y2: int) -> Tuple[int, int]:
        if x1 == x2 and y1 == y2:
            s = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p) % self.p
        else:
            s = (y2 - y1) * self._mod_inverse(x2 - x1, self.p) % self.p

        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        return x3, y3

    def _point_multiply(self, x: int, y: int, scalar: int) -> Tuple[int, int]:
        if scalar == 0:
            return None, None
        if scalar == 1:
            return x, y

        result_x, result_y = None, None
        add_x, add_y = x, y

        while scalar > 0:
            if scalar & 1:
                if result_x is None:
                    result_x, result_y = add_x, add_y
                else:
                    result_x, result_y = self._point_add(result_x, result_y, add_x, add_y)
            add_x, add_y = self._point_add(add_x, add_y, add_x, add_y)
            scalar >>= 1

        return result_x, result_y

    def _generate_H_point(self) -> Tuple[int, int]:
        counter = 0
        while True:
            data = f"pedersen_H_{counter}".encode()
            hash_bytes = hashlib.sha256(data).digest()
            x_candidate = int.from_bytes(hash_bytes, 'big') % self.p

            y_squared = (pow(x_candidate, 3, self.p) + self.a * x_candidate + self.b) % self.p

            y_candidate = pow(y_squared, (self.p + 1) // 4, self.p)
            if pow(y_candidate, 2, self.p) == y_squared:
                Hx, Hy = self._point_multiply(x_candidate, y_candidate, 2)
                if Hx is not None and Hx != self.Gx:
                    return Hx, Hy
            counter += 1

    def pedersen_commit(self, s: int, t: int) -> Tuple[int, int]:
        sGx, sGy = self._point_multiply(self.Gx, self.Gy, s % self.order)
        tHx, tHy = self._point_multiply(self.Hx, self.Hy, t % self.order)

        if sGx is None:
            return tHx, tHy
        if tHx is None:
            return sGx, sGy

        return self._point_add(sGx, sGy, tHx, tHy)

    def generate_polynomial(self, secret: int, degree: int) -> List[int]:
        coefficients = [secret % self.order]
        for _ in range(degree):
            coeff = secrets.randbelow(self.order)
            coefficients.append(coeff)
        return coefficients

    def evaluate_polynomial(self, coeffs: List[int], x: int) -> int:
        result = 0
        x_power = 1
        for coeff in coeffs:
            result = (result + coeff * x_power) % self.order
            x_power = (x_power * x) % self.order
        return result

    def lagrange_coefficient(self, indices: List[int], i: int) -> int:
        numerator = 1
        denominator = 1
        for j in indices:
            if j != i:
                numerator = (numerator * (-j)) % self.order
                denominator = (denominator * (i - j)) % self.order
        return (numerator * self._mod_inverse(denominator, self.order)) % self.order


class StandardVSS:
    def __init__(self, n: int = 100, t: int = 50):
        self.vss = StandardPedersenVSS(n, t)
        self.n = n
        self.t = t

    def vss_gen(self, secret: int) -> Tuple:
        start_time = time.time()

        blinding = secrets.randbelow(self.vss.order)

        E0 = self.vss.pedersen_commit(secret, blinding)

        F_coeffs = self.vss.generate_polynomial(secret, self.t - 1)
        G_coeffs = self.vss.generate_polynomial(blinding, self.t - 1)

        E_poly = []
        for j in range(self.t):
            F_j = F_coeffs[j] if j < len(F_coeffs) else 0
            G_j = G_coeffs[j] if j < len(G_coeffs) else 0
            E_j = self.vss.pedersen_commit(F_j, G_j)
            E_poly.append(E_j)

        shares_s = []
        shares_o = []
        for i in range(1, self.n + 1):
            share_s = self.vss.evaluate_polynomial(F_coeffs, i)
            share_o = self.vss.evaluate_polynomial(G_coeffs, i)
            shares_s.append(share_s)
            shares_o.append(share_o)

        gen_time = time.time() - start_time
        return (shares_s, shares_o, E0, E_poly), gen_time

    def vss_verify_share(self, share_s: int, share_o: int, E0: Tuple[int, int],
                         E_poly: List[Tuple[int, int]], party_id: int) -> Tuple[bool, float]:
        start_time = time.time()

        left_side = self.vss.pedersen_commit(share_s, share_o)

        right_side = E0
        x_power = party_id

        for j in range(1, len(E_poly)):
            E_j_x, E_j_y = E_poly[j]
            if E_j_x is not None:
                exp_Ej_x, exp_Ej_y = self.vss._point_multiply(E_j_x, E_j_y, x_power)
                if exp_Ej_x is not None:
                    right_side = self.vss._point_add(right_side[0], right_side[1], exp_Ej_x, exp_Ej_y)
            x_power = (x_power * party_id) % self.vss.order

        verify_time = time.time() - start_time

        points_equal = (left_side[0] == right_side[0] and left_side[1] == right_side[1])
        return points_equal, verify_time

    def vss_rec(self, shares_s: List[int], shares_o: List[int],
                indices: List[int]) -> Tuple[int, int, float]:
        start_time = time.time()

        lagrange_coeffs = []
        for i in indices:
            lambda_i = self.vss.lagrange_coefficient(indices, i)
            lagrange_coeffs.append(lambda_i)

        recovered_s = 0
        recovered_o = 0
        for i, (lambda_i, share_s, share_o) in enumerate(zip(lagrange_coeffs, shares_s, shares_o)):
            recovered_s = (recovered_s + lambda_i * share_s) % self.vss.order
            recovered_o = (recovered_o + lambda_i * share_o) % self.vss.order

        rec_time = time.time() - start_time
        return recovered_s, recovered_o, rec_time


def benchmark_standard_vss():
    print("NIST P-256标准Pedersen VSS基准测试")
    print("=" * 50)

    n = 100
    t = 50

    vss = StandardVSS(n, t)
    secret = secrets.randbelow(vss.vss.order)

    print(f"参数: n={n}, t={t}")
    print(f"秘密: {secret}")
    print()

    print("1. 份额生成")
    (shares_s, shares_o, E0, E_poly), gen_time = vss.vss_gen(secret)
    print(f"生成时间: {gen_time:.6f}秒")
    print(f"生成份额: {len(shares_s)}个")
    print()

    print("2. 份额验证")
    valid, verify_time = vss.vss_verify_share(shares_s[0], shares_o[0], E0, E_poly, 1)
    print(f"验证时间: {verify_time:.6f}秒")
    print(f"验证结果: {valid}")
    print()

    print("3. 秘密重构")
    indices = list(range(1, t + 1))
    recovered_s, recovered_o, rec_time = vss.vss_rec(
        shares_s[:t], shares_o[:t], indices[:t]
    )
    print(f"重构时间: {rec_time:.6f}秒")
    print(f"重构成功: {secret == recovered_s}")
    print()

    print("性能总结:")
    print("=" * 30)
    print(f"份额生成时间: {gen_time:.6f}秒")
    print(f"单个份额验证时间: {verify_time:.6f}秒")
    print(f"秘密重构时间: {rec_time:.6f}秒")


if __name__ == "__main__":
    benchmark_standard_vss()