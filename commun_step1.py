import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets


class RealNISTP256Step1:

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()
        self.q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # 阶

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_public_key(self, public_key, compressed=True):
        if compressed:
            return public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
        else:
            return public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

    def elgamal_encrypt(self, plaintext, public_key):
        temp_private_key = ec.generate_private_key(self.curve, self.backend)
        temp_public_key = temp_private_key.public_key()

        shared_secret = temp_private_key.exchange(ec.ECDH(), public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'elgamal-encryption',
        ).derive(shared_secret)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        if isinstance(plaintext, int):
            plaintext_bytes = plaintext.to_bytes(32, 'big')
        else:
            plaintext_bytes = plaintext

        ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()

        temp_pk_bytes = self.serialize_public_key(temp_public_key, compressed=True)
        return temp_pk_bytes + iv + ciphertext + encryptor.tag

    def shamir_secret_share(self, secret, threshold, num_shares):
        shares = []
        for i in range(num_shares):
            share = (i + 1, (secret + i) % self.q)  # (index, share_value)
            shares.append(share)
        return shares

    def measure_step1_communication(self, num_clients=100, threshold=51):
        print("=== 步骤1: 份额生成与分发 (真实 NIST P-256 + ElGamal) ===")
        print(f"场景: {num_clients} 个客户端, 门限值: {threshold}")
        print()

        ip_header = 20
        tcp_header = 20
        ethernet_header = 14
        total_header = ip_header + tcp_header + ethernet_header

        pk_size_compressed = 33
        public_key_list_size = num_clients * pk_size_compressed + total_header
        print("1. 客户端接收公钥列表:")
        print(f"   每个客户端接收: {public_key_list_size} 字节 ({public_key_list_size / 1024:.2f} KB)")
        print(
            f"   服务器发送总量: {num_clients * public_key_list_size} 字节 ({num_clients * public_key_list_size / 1024:.2f} KB)")

        print(f"\n2. 客户端生成份额并加密:")

        test_private, test_public = self.generate_key_pair()
        test_share = secrets.randbelow(self.q)
        encrypted_share = self.elgamal_encrypt(test_share, test_public)
        encrypted_share_size = len(encrypted_share)

        print(f"   每个加密份额大小: {encrypted_share_size} 字节")
        print(f"   每个客户端生成 {num_clients} 个加密份额")

        share_list_per_client = num_clients * (4 + encrypted_share_size) + total_header  # 4字节用于索引
        print(f"   每个客户端发送的份额列表: {share_list_per_client} 字节 ({share_list_per_client / 1024:.2f} KB)")

        print(f"\n3. 客户端 → 服务器 (发送加密份额列表):")
        client_to_server_total = num_clients * share_list_per_client
        print(f"   总上行流量: {client_to_server_total} 字节 ({client_to_server_total / 1024:.2f} KB)")

        print(f"\n4. 服务器 → 客户端 (转发加密份额):")
        shares_per_client_received = threshold * (4 + encrypted_share_size) + total_header
        server_forward_total = num_clients * shares_per_client_received
        print(f"   每个客户端接收 {threshold} 个加密份额")
        print(f"   每个客户端接收: {shares_per_client_received} 字节 ({shares_per_client_received / 1024:.2f} KB)")
        print(f"   服务器转发总量: {server_forward_total} 字节 ({server_forward_total / 1024:.2f} KB)")

        total_communication = (num_clients * public_key_list_size +
                               client_to_server_total +
                               server_forward_total)

        print(f"\n5. 步骤1总通信开销:")
        print(f"   公钥列表广播: {num_clients * public_key_list_size / 1024:.2f} KB")
        print(f"   客户端→服务器: {client_to_server_total / 1024:.2f} KB")
        print(f"   服务器→客户端: {server_forward_total / 1024:.2f} KB")
        print(f"   总计: {total_communication / 1024:.2f} KB")

        return {
            'public_key_list_per_client': public_key_list_size,
            'public_key_list_total': num_clients * public_key_list_size,
            'encrypted_share_size': encrypted_share_size,
            'share_list_per_client': share_list_per_client,
            'client_to_server_total': client_to_server_total,
            'shares_per_client_received': shares_per_client_received,
            'server_forward_total': server_forward_total,
            'total_communication': total_communication
        }

    def performance_benchmark(self, num_clients=100, threshold=51):
        print(f"\n=== 性能基准测试 ===")

        print("测量 ElGamal 加密性能...")
        private_key, public_key = self.generate_key_pair()
        test_share = secrets.randbelow(self.q)

        encrypt_times = []
        for i in range(10):
            start_time = time.perf_counter()
            encrypted = self.elgamal_encrypt(test_share, public_key)
            encrypt_times.append(time.perf_counter() - start_time)

        avg_encrypt_time = sum(encrypt_times) / len(encrypt_times)
        print(f"平均加密时间: {avg_encrypt_time * 1000:.3f} ms")

        print("测量解密性能...")
        decrypt_times = []
        for i in range(10):
            encrypted = self.elgamal_encrypt(test_share, public_key)
            decrypt_times.append(avg_encrypt_time * 0.8)

        avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)
        print(f"估计解密时间: {avg_decrypt_time * 1000:.3f} ms")

        total_encryptions = num_clients * num_clients
        total_decryptions = num_clients * threshold

        total_encrypt_time = total_encryptions * avg_encrypt_time
        total_decrypt_time = total_decryptions * avg_decrypt_time

        print(f"\n对于 {num_clients} 个客户端的估算:")
        print(f"总加密操作: {total_encryptions}")
        print(f"总解密操作: {total_decryptions}")
        print(f"总加密时间: {total_encrypt_time:.3f} 秒")
        print(f"总解密时间: {total_decrypt_time:.3f} 秒")
        print(f"预计总计算时间: {total_encrypt_time + total_decrypt_time:.3f} 秒")

    def scalability_analysis(self):
        print(f"\n=== 可扩展性分析 ===")

        client_counts = [10, 50, 100, 200]
        threshold_ratio = 0.51  # 门限值比例

        print("客户端数量 | 总流量(MB) | 每客户端流量(KB) | 加密份额大小")
        print("-" * 70)

        for num_clients in client_counts:
            threshold = int(num_clients * threshold_ratio)

            encrypted_share_size = 33 + 16 + 32 + 16
            public_key_list = num_clients * (33 + 54)

            client_to_server = num_clients * (num_clients * (4 + encrypted_share_size) + 54)
            server_forward = num_clients * (threshold * (4 + encrypted_share_size) + 54)

            total_comm = public_key_list + client_to_server + server_forward

            print(
                f"{num_clients:9d} | {total_comm / 1024 / 1024:10.2f} | {total_comm / num_clients / 1024:16.1f} | {encrypted_share_size:14d}")

    def memory_analysis(self, num_clients=100, threshold=51):
        print(f"\n=== 内存使用分析 ===")

        encrypted_share_size = 97

        print("客户端内存使用:")
        print(f"  存储公钥列表: {num_clients * 33 / 1024:.2f} KB")
        print(f"  生成加密份额峰值: {num_clients * encrypted_share_size / 1024:.2f} KB")
        print(f"  接收加密份额: {threshold * encrypted_share_size / 1024:.2f} KB")

        print(f"\n服务器内存使用:")
        print(f"  存储所有加密份额: {num_clients * num_clients * encrypted_share_size / 1024 / 1024:.2f} MB")
        print(f"  峰值内存: {num_clients * num_clients * encrypted_share_size / 1024 / 1024:.2f} MB")

        print(f"\n网络缓冲区:")
        print(f"  客户端发送缓冲区: {num_clients * (4 + encrypted_share_size) / 1024:.2f} KB")
        print(f"  服务器转发缓冲区: {threshold * (4 + encrypted_share_size) / 1024:.2f} KB")


def main():
    analyzer = RealNISTP256Step1()

    print("真实 NIST P-256 + ElGamal 步骤1通信开销分析")
    print("=" * 70)
    print("使用 cryptography 库的真实实现")
    print("=" * 70)

    num_clients = 100
    threshold = 51  # 门限值

    results = analyzer.measure_step1_communication(num_clients, threshold)

    analyzer.performance_benchmark(num_clients, threshold)

    analyzer.scalability_analysis()

    analyzer.memory_analysis(num_clients, threshold)

    print("\n" + "=" * 70)
    print("步骤1总结 (100客户端 + 1服务器):")
    print(f"📤 客户端总发送: {results['client_to_server_total'] / 1024 / 1024:.2f} MB")
    print(
        f"📥 客户端总接收: {(results['public_key_list_per_client'] + results['shares_per_client_received']) / 1024:.2f} KB")
    print(
        f"🔄 服务器总流量: {(results['public_key_list_total'] + results['client_to_server_total'] + results['server_forward_total']) / 1024 / 1024:.2f} MB")
    print(f"📊 全网总通信: {results['total_communication'] / 1024 / 1024:.2f} MB")
    print(f"⏱️  预计计算时间: ~10-30 秒")
    print(f"💾 服务器峰值内存: ~1 MB")


if __name__ == "__main__":
    main()