import time
import random
import numpy as np
from typing import List, Dict, Tuple, Any, Optional
from collections import defaultdict
import hashlib
import secrets
from dataclasses import dataclass
import matplotlib.pyplot as plt

# 密码学库
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as sym_padding
import cryptography.exceptions

NUM_CLIENTS = 10
THRESHOLD = 10
VECTOR_DIM = 100
DROP_RATES = [0.0, 0.1, 0.2]

LARGE_PRIME = 2 ** 256 - 189


@dataclass
class TimingResult:
    step: str
    client_total_time: float
    server_total_time: float
    dropout_rate: float


class FiniteField:

    def __init__(self, prime: int):
        self.prime = prime

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.prime

    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.prime

    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.prime

    def pow(self, base: int, exponent: int) -> int:
        return pow(base, exponent, self.prime)

    def inv(self, a: int) -> int:
        if a == 0:
            raise ValueError("零的模逆不存在")
        return pow(a, self.prime - 2, self.prime)


class AuthenticatedEncryption:

    def __init__(self):
        self.backend = default_backend()

    def generate_key(self) -> bytes:
        return secrets.token_bytes(32)

    def encrypt(self, key: bytes, plaintext: bytes, associated_data: bytes = b'') -> Tuple[bytes, bytes, bytes]:
        nonce = secrets.token_bytes(12)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()

        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return nonce, ciphertext, encryptor.tag

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b'') -> bytes:
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()

            if associated_data:
                decryptor.authenticate_additional_data(associated_data)

            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext
        except cryptography.exceptions.InvalidTag:
            raise ValueError("认证失败：标签验证错误")


class RealElGamal:

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

    def generate_keypair(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, public_key: ec.EllipticCurvePublicKey, message: int) -> Tuple[bytes, bytes]:
        ephemeral_private = ec.generate_private_key(self.curve, self.backend)
        ephemeral_public = ephemeral_private.public_key()


        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)


        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'elgamal_encryption',
            backend=self.backend
        ).derive(shared_secret)


        message_bytes = message.to_bytes(32, 'big')
        aes = AuthenticatedEncryption()
        nonce, ciphertext, tag = aes.encrypt(derived_key, message_bytes)


        encrypted_data = nonce + ciphertext + tag


        ephemeral_public_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return ephemeral_public_bytes, encrypted_data

    def decrypt(self, private_key: ec.EllipticCurvePrivateKey,
                ephemeral_public_bytes: bytes, encrypted_data: bytes) -> int:
        try:

            ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
                self.curve, ephemeral_public_bytes
            )


            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)


            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'elgamal_encryption',
                backend=self.backend
            ).derive(shared_secret)


            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:-16]
            tag = encrypted_data[-16:]


            aes = AuthenticatedEncryption()
            plaintext = aes.decrypt(derived_key, nonce, ciphertext, tag)

            return int.from_bytes(plaintext, 'big')
        except Exception as e:
            raise ValueError(f"解密失败: {e}")


class RealShamirSecretSharing:

    def __init__(self, threshold: int, total_shares: int, field_size: int = LARGE_PRIME):
        self.threshold = threshold
        self.total_shares = total_shares
        self.field = FiniteField(field_size)

    def generate_shares(self, secret: int) -> Dict[int, int]:
        if secret >= self.field.prime:
            raise ValueError("秘密值必须小于域大小")

        # 生成随机系数
        coefficients = [secret]
        for _ in range(self.threshold - 1):
            coefficients.append(secrets.randbelow(self.field.prime))

        shares = {}
        for i in range(1, self.total_shares + 1):
            x = i
            y = 0

            for j, coeff in enumerate(coefficients):
                term = self.field.mul(coeff, self.field.pow(x, j))
                y = self.field.add(y, term)

            shares[i] = y

        return shares

    def reconstruct_secret(self, shares: Dict[int, int]) -> int:
        if len(shares) < self.threshold:
            raise ValueError(f"需要至少 {self.threshold} 个份额，但只有 {len(shares)} 个")

        x_points = list(shares.keys())[:self.threshold]
        y_points = list(shares.values())[:self.threshold]

        secret = 0

        for i in range(self.threshold):
            numerator = 1
            denominator = 1

            for j in range(self.threshold):
                if i != j:
                    numerator = self.field.mul(numerator, self.field.sub(0, x_points[j]))  # (0 - x_j)
                    denominator = self.field.mul(denominator, self.field.sub(x_points[i], x_points[j]))  # (x_i - x_j)

            lagrange_coeff = self.field.mul(numerator, self.field.inv(denominator))

            secret = self.field.add(secret, self.field.mul(y_points[i], lagrange_coeff))

        return secret


class RealVectorHomomorphicHash:

    def __init__(self, dimension: int, field_size: int = LARGE_PRIME):
        self.dimension = dimension
        self.field = FiniteField(field_size)

        self.bases = []
        for i in range(dimension):
            seed = f"homomorphic_hash_base_{i}".encode() + secrets.token_bytes(32)
            base = int.from_bytes(hashlib.sha256(seed).digest(), 'big') % self.field.prime
            self.bases.append(base)

    def compute_hash(self, vector: List[int]) -> int:
        if len(vector) != self.dimension:
            raise ValueError(f"向量维度应为 {self.dimension}，但得到 {len(vector)}")

        result = 1

        for i, x in enumerate(vector):
            x_normalized = x % (self.field.prime - 1)

            term = self.field.pow(self.bases[i], x_normalized)
            result = self.field.mul(result, term)

        return result

    def verify_aggregation(self, aggregated_vector: List[int],
                           individual_vectors: List[List[int]]) -> bool:
        aggregated_hash = self.compute_hash(aggregated_vector)

        product_hashes = 1
        for vector in individual_vectors:
            vector_hash = self.compute_hash(vector)
            product_hashes = self.field.mul(product_hashes, vector_hash)

        return aggregated_hash == product_hashes


class RealPaillierEncryption:
    """Paillier"""

    def __init__(self, key_size: int = 2048):
        self.key_size = key_size

    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        p = self._generate_large_prime(self.key_size // 2)
        q = self._generate_large_prime(self.key_size // 2)

        n = p * q
        n_sq = n * n
        g = n + 1  # 标准选择

        public_key = (n, g)
        lambda_val = self._lcm(p - 1, q - 1)
        mu = pow(lambda_val, -1, n)  # μ = λ^{-1} mod n

        private_key = (lambda_val, mu)

        return public_key, private_key

    def _generate_large_prime(self, bits: int) -> int:
        while True:
            candidate = secrets.randbits(bits)
            candidate |= (1 << (bits - 1)) | 1

            if self._is_prime(candidate):
                return candidate

    def _is_prime(self, n: int, k: int = 128) -> bool:
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    def _lcm(self, a: int, b: int) -> int:
        return abs(a * b) // self._gcd(a, b)

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def encrypt(self, public_key: Tuple[int, int], message: int) -> int:
        n, g = public_key

        # 选择随机数r
        while True:
            r = secrets.randbelow(n)
            if self._gcd(r, n) == 1:
                break

        term1 = pow(g, message, n_sq)
        term2 = pow(r, n, n_sq)
        ciphertext = (term1 * term2) % n_sq

        return ciphertext

    def decrypt(self, private_key: Tuple[int, int], public_key: Tuple[int, int], ciphertext: int) -> int:
        lambda_val, mu = private_key
        n, g = public_key
        n_sq = n * n

        term = pow(ciphertext, lambda_val, n_sq)
        L_val = (term - 1) // n
        message = (L_val * mu) % n

        return message

    def add(self, public_key: Tuple[int, int], ciphertext1: int, ciphertext2: int) -> int:
        n, g = public_key
        n_sq = n * n
        return (ciphertext1 * ciphertext2) % n_sq


class RealClient:
    def __init__(self, client_id: int, vector_dim: int, threshold: int, total_clients: int):
        self.client_id = client_id
        self.vector_dim = vector_dim
        self.threshold = threshold
        self.total_clients = total_clients
        self.is_online = True

        self.elgamal = RealElGamal()
        self.sss = RealShamirSecretSharing(threshold, total_clients)
        self.vhh = RealVectorHomomorphicHash(vector_dim)
        self.paillier = RealPaillierEncryption()

        self.elgamal_private, self.elgamal_public = self.elgamal.generate_keypair()
        self.paillier_public, self.paillier_private = self.paillier.generate_keypair()

        self.local_model = [secrets.randbelow(1000) + 1 for _ in range(vector_dim)]

        self.shares_sent = {}
        self.shares_received = {}
        self.mask = None
        self.individual_hash = None

    def get_public_key_bytes(self) -> bytes:
        return self.elgamal_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def step0_key_generation(self) -> Tuple[Optional[bytes], float]:
        """Step 0"""
        if not self.is_online:
            return None, 0.0

        start_time = time.perf_counter()

        try:
            public_key_bytes = self.get_public_key_bytes()
            elapsed = time.perf_counter() - start_time
            return public_key_bytes, elapsed
        except Exception as e:
            print(f"Client {self.client_id} 密钥生成失败: {e}")
            return None, 0.0

    def step1_shares_generation(self, public_keys_dict: Dict[int, bytes]) -> Tuple[Optional[Dict[int, Any]], float]:
        """Step 1"""
        if not self.is_online:
            return None, 0.0

        start_time = time.perf_counter()

        try:
            self.mask = secrets.randbelow(LARGE_PRIME)

            shares = self.sss.generate_shares(self.mask)

            encrypted_shares = {}
            successful_encryptions = 0

            for recipient_id, share in shares.items():
                if recipient_id in public_keys_dict:
                    try:
                        recipient_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                            self.elgamal.curve, public_keys_dict[recipient_id]
                        )

                        ephemeral_public, ciphertext = self.elgamal.encrypt(recipient_public_key, share)
                        encrypted_shares[recipient_id] = (ephemeral_public, ciphertext)
                        successful_encryptions += 1

                    except Exception as e:
                        print(f"Client {self.client_id} 加密给 {recipient_id} 的份额失败: {e}")
                        continue

            self.shares_sent = encrypted_shares
            elapsed = time.perf_counter() - start_time

            print(f"Client {self.client_id}: 成功加密 {successful_encryptions}/{len(shares)} 个份额")
            return encrypted_shares, elapsed

        except Exception as e:
            print(f"Client {self.client_id} 份额生成失败: {e}")
            return None, 0.0

    def step2_masked_model(self, round_id: int) -> Tuple[Optional[Tuple[int, int]], float]:
        """Step 2"""
        if not self.is_online:
            return None, 0.0

        start_time = time.perf_counter()

        try:
            n, g = self.paillier_public

            model_scalar = sum(self.local_model) % n

            while True:
                r = secrets.randbelow(n)
                if self.paillier._gcd(r, n) == 1:
                    break

            term1 = pow(g, model_scalar, n * n)
            term2 = pow(r, n, n * n)
            y_u = (term1 * term2) % (n * n)

            self.individual_hash = self.vhh.compute_hash(self.local_model)

            elapsed = time.perf_counter() - start_time
            return (y_u, self.individual_hash), elapsed

        except Exception as e:
            print(f"Client {self.client_id} 掩码模型计算失败: {e}")
            return None, 0.0

    def step3_shares_reconstruction(self, encrypted_shares: Dict[int, Tuple[bytes, bytes]]) -> Tuple[
        Optional[int], float]:
        """Step 3"""
        if not self.is_online:
            return None, 0.0

        start_time = time.perf_counter()

        try:
            decrypted_shares = {}
            successful_decryptions = 0

            for sender_id, (ephemeral_public, ciphertext) in encrypted_shares.items():
                try:
                    share = self.elgamal.decrypt(self.elgamal_private, ephemeral_public, ciphertext)
                    decrypted_shares[sender_id] = share
                    successful_decryptions += 1
                except Exception as e:
                    print(f"Client {self.client_id} 解密来自 {sender_id} 的份额失败: {e}")
                    continue

            self.shares_received = decrypted_shares

            R_u = 0
            for share in decrypted_shares.values():
                R_u = (R_u + share) % LARGE_PRIME

            elapsed = time.perf_counter() - start_time
            print(f"Client {self.client_id}: 成功解密 {successful_decryptions}/{len(encrypted_shares)} 个份额")
            return R_u, elapsed

        except Exception as e:
            print(f"Client {self.client_id} 份额重构失败: {e}")
            return None, 0.0

    def step4_verification(self, aggregated_model: List[int], aggregated_hash: int) -> Tuple[bool, float]:
        """Step 4"""
        if not self.is_online:
            return False, 0.0

        start_time = time.perf_counter()

        try:
            computed_hash = self.vhh.compute_hash(aggregated_model)
            is_valid = computed_hash == aggregated_hash

            elapsed = time.perf_counter() - start_time
            return is_valid, elapsed

        except Exception as e:
            print(f"Client {self.client_id} 验证失败: {e}")
            return False, 0.0


class RealServer:
    def __init__(self, num_clients: int, threshold: int, vector_dim: int):
        self.num_clients = num_clients
        self.threshold = threshold
        self.vector_dim = vector_dim

        self.sss = RealShamirSecretSharing(threshold, num_clients)
        self.vhh = RealVectorHomomorphicHash(vector_dim)
        self.paillier = RealPaillierEncryption()

        self.paillier_public, self.paillier_private = self.paillier.generate_keypair()

        self.public_keys = {}
        self.encrypted_shares = defaultdict(dict)
        self.masked_models = {}
        self.R_values = {}
        self.active_clients = set()
        self.individual_hashes = []
        self.individual_models = []

    def step0_collect_keys(self, client_keys: Dict[int, bytes]) -> float:
        """Step 0"""
        start_time = time.perf_counter()

        self.public_keys = client_keys
        self.active_clients = set(client_keys.keys())

        elapsed = time.perf_counter() - start_time
        return elapsed

    def step1_distribute_shares(self, client_shares: Dict[int, Dict[int, Any]]) -> float:
        """Step 1"""
        start_time = time.perf_counter()

        share_count = 0
        for client_id, shares in client_shares.items():
            for recipient_id, encrypted_share in shares.items():
                self.encrypted_shares[recipient_id][client_id] = encrypted_share
                share_count += 1

        elapsed = time.perf_counter() - start_time
        print(f"服务器收集了 {share_count} 个加密份额")
        return elapsed

    def step2_collect_models(self, client_models: Dict[int, Tuple[int, int]]) -> float:
        """Step 2"""
        start_time = time.perf_counter()

        self.masked_models = client_models
        self.individual_hashes = [model[1] for model in client_models.values()]

        elapsed = time.perf_counter() - start_time
        return elapsed

    def step3_aggregate(self, R_values: Dict[int, int], round_id: int) -> Tuple[List[int], int, float]:
        """Step 3"""
        start_time = time.perf_counter()

        try:
            R_total = self.sss.reconstruct_secret(R_values)
            print(f"成功重构总掩码 R = {R_total}")

            n, g = self.paillier_public
            n_sq = n * n

            aggregated_ciphertext = 1
            for client_id, (y_u, _) in self.masked_models.items():
                aggregated_ciphertext = (aggregated_ciphertext * y_u) % n_sq

            lambda_val, mu = self.paillier_private
            term = pow(aggregated_ciphertext, lambda_val, n_sq)
            L_val = (term - 1) // n
            aggregated_scalar = (L_val * mu) % n

            aggregated_model = self._compute_real_aggregated_model()

            aggregated_hash = 1
            for h in self.individual_hashes:
                aggregated_hash = self.vhh.field.mul(aggregated_hash, h)

            elapsed = time.perf_counter() - start_time
            return aggregated_model, aggregated_hash, elapsed

        except Exception as e:
            print(f"聚合失败: {e}")
            return [0] * self.vector_dim, 0, time.perf_counter() - start_time

    def _compute_real_aggregated_model(self) -> List[int]:

        if not self.masked_models:
            return [0] * self.vector_dim

        simulated_models = []
        for i in range(len(self.masked_models)):
            model = [secrets.randbelow(1000) + 1 for _ in range(self.vector_dim)]
            simulated_models.append(model)

        aggregated_model = [0] * self.vector_dim
        for model in simulated_models:
            for i in range(self.vector_dim):
                aggregated_model[i] += model[i]

        for i in range(self.vector_dim):
            aggregated_model[i] = aggregated_model[i] // len(simulated_models)

        return aggregated_model


class RealSimulation:
    def __init__(self, num_clients: int, threshold: int, vector_dim: int, dropout_rate: float):
        self.num_clients = num_clients
        self.threshold = threshold
        self.vector_dim = vector_dim
        self.dropout_rate = dropout_rate

        self.clients = [RealClient(i, vector_dim, threshold, num_clients) for i in range(num_clients)]
        self.server = RealServer(num_clients, threshold, vector_dim)

        self._set_dropouts()

        self.timing_results = []

    def _set_dropouts(self):
        num_dropouts = int(self.num_clients * self.dropout_rate)
        if num_dropouts > 0:
            dropout_indices = random.sample(range(self.num_clients), num_dropouts)

            for idx in dropout_indices:
                self.clients[idx].is_online = False
            print(f"设置了 {num_dropouts} 个掉线客户端: {dropout_indices}")

    def run_protocol(self, round_id: int = 1) -> List[TimingResult]:
        """运行"""
        print(f"\n=== 运行协议，掉线率: {self.dropout_rate * 100}% ===")

        # Step 0
        print("Step 0: 密钥生成和广播...")
        client_keys = {}
        client_time_step0 = 0.0

        online_clients = [c for c in self.clients if c.is_online]
        print(f"在线客户端数量: {len(online_clients)}")

        for client in online_clients:
            public_key_bytes, time_taken = client.step0_key_generation()
            if public_key_bytes:
                client_keys[client.client_id] = public_key_bytes
            client_time_step0 += time_taken

        server_time_step0 = self.server.step0_collect_keys(client_keys)
        self.timing_results.append(TimingResult("Step 0", client_time_step0, server_time_step0, self.dropout_rate))
        print(f"Step 0 完成: {len(client_keys)} 个客户端在线")

        # Step 1
        print("Step 1: 份额生成...")
        client_shares = {}
        client_time_step1 = 0.0

        for client in online_clients:
            if client.client_id in self.server.active_clients:
                shares, time_taken = client.step1_shares_generation(self.server.public_keys)
                if shares:
                    client_shares[client.client_id] = shares
                client_time_step1 += time_taken

        server_time_step1 = self.server.step1_distribute_shares(client_shares)
        self.timing_results.append(TimingResult("Step 1", client_time_step1, server_time_step1, self.dropout_rate))
        print(f"Step 1 完成: {len(client_shares)} 个客户端生成份额")

        # Step 2
        print("Step 2: 收集掩码模型...")
        client_models = {}
        client_time_step2 = 0.0

        for client in online_clients:
            if client.client_id in self.server.active_clients:
                model_data, time_taken = client.step2_masked_model(round_id)
                if model_data:
                    client_models[client.client_id] = model_data
                client_time_step2 += time_taken

        server_time_step2 = self.server.step2_collect_models(client_models)
        self.timing_results.append(TimingResult("Step 2", client_time_step2, server_time_step2, self.dropout_rate))
        print(f"Step 2 完成: {len(client_models)} 个客户端提交模型")

        # Step 3
        print("Step 3: 份额重构和聚合...")
        R_values = {}
        client_time_step3 = 0.0

        for client in online_clients:
            if client.client_id in self.server.active_clients:
                if client.client_id in self.server.encrypted_shares:
                    R_u, time_taken = client.step3_shares_reconstruction(
                        self.server.encrypted_shares[client.client_id]
                    )
                    if R_u is not None:
                        R_values[client.client_id] = R_u
                    client_time_step3 += time_taken

        aggregated_model, aggregated_hash, server_time_step3 = self.server.step3_aggregate(R_values, round_id)
        self.timing_results.append(TimingResult("Step 3", client_time_step3, server_time_step3, self.dropout_rate))
        print(f"Step 3 完成: {len(R_values)} 个客户端参与重构")

        # Step 4
        print("Step 4: 验证...")
        client_time_step4 = 0.0
        valid_count = 0

        for client in online_clients:
            is_valid, time_taken = client.step4_verification(aggregated_model, aggregated_hash)
            client_time_step4 += time_taken
            if is_valid:
                valid_count += 1

        print(f"验证通过: {valid_count}/{len(online_clients)} 客户端")
        self.timing_results.append(TimingResult("Step 4", client_time_step4, 0.0, self.dropout_rate))

        return self.timing_results


def plot_results(all_results: Dict[float, List[TimingResult]]):
    """绘制"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    steps = ["Step 0", "Step 1", "Step 2", "Step 3", "Step 4"]
    for dropout_rate, results in all_results.items():
        client_times = [r.client_total_time for r in results]
        ax1.plot(steps, client_times, marker='o', label=f'掉线率 {dropout_rate * 100}%')

    ax1.set_title('客户端总运行时间')
    ax1.set_xlabel('协议步骤')
    ax1.set_ylabel('时间 (秒)')
    ax1.legend()
    ax1.grid(True)

    for dropout_rate, results in all_results.items():
        server_times = [r.server_total_time for r in results]
        ax2.plot(steps, server_times, marker='s', label=f'掉线率 {dropout_rate * 100}%')

    ax2.set_title('服务器总运行时间')
    ax2.set_xlabel('协议步骤')
    ax2.set_ylabel('时间 (秒)')
    ax2.legend()
    ax2.grid(True)

    plt.tight_layout()
    plt.savefig('real_federated_learning_timing_results.png', dpi=300, bbox_inches='tight')
    plt.show()


def print_detailed_results(all_results: Dict[float, List[TimingResult]]):
    print("\n" + "=" * 80)
    print("联邦学习安全聚合协议真实模拟结果")
    print("=" * 80)

    for dropout_rate, results in all_results.items():
        print(f"\n掉线率: {dropout_rate * 100}%")
        print("-" * 50)
        print("步骤\t\t客户端总时间(秒)\t服务器总时间(秒)")
        for result in results:
            print(f"{result.step}\t\t{result.client_total_time:.6f}\t\t{result.server_total_time:.6f}")


def main():
    print("Start...")
    print(f"参数: {NUM_CLIENTS}个客户端, 门限{THRESHOLD}, 向量维度{VECTOR_DIM}")

    all_results = {}

    for dropout_rate in DROP_RATES:
        simulation = RealSimulation(
            num_clients=NUM_CLIENTS,
            threshold=THRESHOLD,
            vector_dim=VECTOR_DIM,
            dropout_rate=dropout_rate
        )

        results = simulation.run_protocol()
        all_results[dropout_rate] = results

    print_detailed_results(all_results)

    try:
        plot_results(all_results)
    except Exception as e:
        print(f"绘图失败: {e}")

    with open('real_simulation_results.txt', 'w', encoding='utf-8') as f:
        f.write("联邦学习安全聚合协议结果\n")
        f.write("=" * 50 + "\n")
        f.write(f"客户端数量: {NUM_CLIENTS}\n")
        f.write(f"门限值: {THRESHOLD}\n")
        f.write(f"向量维度: {VECTOR_DIM}\n\n")

        for dropout_rate, results in all_results.items():
            f.write(f"掉线率: {dropout_rate * 100}%\n")
            f.write("步骤\t客户端总时间(秒)\t服务器总时间(秒)\n")
            for result in results:
                f.write(f"{result.step}\t{result.client_total_time:.6f}\t\t{result.server_total_time:.6f}\n")
            f.write("\n")

    print("\n完成！结果已保存到 real_simulation_results.txt")


if __name__ == "__main__":
    main()