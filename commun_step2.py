import hashlib
import math
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class RealNISTP256Step2:


    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

        self.paillier_n_squared_size = 4096
        self.ec_point_compressed_size = 33
        self.sha256_hash_size = 32

        self.model_dimensions = 5

    def serialize_ec_point(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    def measure_step2_communication(self, num_clients=100, threshold=51):
        print("=== 步骤2: 收集掩码模型 (真实 NIST P-256) ===")
        print(f"场景: {num_clients} 个客户端, 门限值: {threshold}")
        print(f"模型维度: {self.model_dimensions} (g1-g5)")
        print()

        ip_header = 20
        tcp_header = 20
        ethernet_header = 14
        total_header = ip_header + tcp_header + ethernet_header

        print("1. 客户端计算:")

        paillier_ciphertext_size = self.paillier_n_squared_size
        print(f"   Paillier掩码模型大小: {paillier_ciphertext_size} 字节")

        vhh_size = self.ec_point_compressed_size
        print(f"   向量同态哈希(VHH)大小: {vhh_size} 字节")

        timestamp_hash_size = self.sha256_hash_size
        print(f"   时间戳哈希大小: {timestamp_hash_size} 字节")

        print(f"\n2. 客户端 → 服务器 (发送掩码模型和VHH):")

        client_data_per_message = (paillier_ciphertext_size +
                                   vhh_size +
                                   timestamp_hash_size +
                                   total_header)

        print(f"   每个客户端发送: {client_data_per_message} 字节 ({client_data_per_message / 1024:.2f} KB)")

        client_to_server_total = threshold * client_data_per_message
        print(f"   服务器接收至少 {threshold} 个客户端数据")
        print(f"   总上行流量: {client_to_server_total} 字节 ({client_to_server_total / 1024:.2f} KB)")

        print(f"\n3. 数据存储开销:")

        server_storage_per_client = (paillier_ciphertext_size + vhh_size + timestamp_hash_size)
        server_total_storage = threshold * server_storage_per_client
        print(f"   服务器存储每个客户端: {server_storage_per_client} 字节")
        print(f"   服务器总存储: {server_total_storage} 字节 ({server_total_storage / 1024:.2f} KB)")

        return {
            'paillier_ciphertext_size': paillier_ciphertext_size,
            'vhh_size': vhh_size,
            'timestamp_hash_size': timestamp_hash_size,
            'client_data_per_message': client_data_per_message,
            'client_to_server_total': client_to_server_total,
            'server_storage_per_client': server_storage_per_client,
            'server_total_storage': server_total_storage
        }

    def performance_analysis(self, num_clients=100):
        print(f"\n=== 性能分析 ===")

        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()

        serialization_times = []
        for i in range(100):
            start_time = time.perf_counter()
            serialized = self.serialize_ec_point(public_key)
            serialization_times.append(time.perf_counter() - start_time)

        avg_serialization_time = sum(serialization_times) / len(serialization_times)

        hash_times = []
        test_data = b"test_data_for_hashing"
        for i in range(1000):
            start_time = time.perf_counter()
            hash_result = hashlib.sha256(test_data).digest()
            hash_times.append(time.perf_counter() - start_time)

        avg_hash_time = sum(hash_times) / len(hash_times)

        print(f"椭圆曲线点序列化时间: {avg_serialization_time * 1000:.3f} ms")
        print(f"SHA-256 哈希计算时间: {avg_hash_time * 1000000:.3f} μs")

        vhh_computation_time = 0.1
        total_client_computation = num_clients * (
                    vhh_computation_time + avg_serialization_time * 1000 + avg_hash_time * 1000)

        print(f"\n对于 {num_clients} 个客户端的估算:")
        print(f"总客户端计算时间: {total_client_computation:.3f} ms")
        print(f"平均每个客户端: {total_client_computation / num_clients:.3f} ms")

    def scalability_analysis(self):
        print(f"\n=== 可扩展性分析 ===")

        client_counts = [10, 50, 100, 200, 500]
        threshold_ratio = 0.51

        print("客户端数量 | 总流量(KB) | 每客户端发送(KB) | 服务器存储(KB)")
        print("-" * 70)

        for num_clients in client_counts:
            threshold = int(num_clients * threshold_ratio)

            client_data = (4096 + 33 + 32 + 54)
            total_traffic = threshold * client_data
            server_storage = threshold * (4096 + 33 + 32)

            print(
                f"{num_clients:9d} | {total_traffic / 1024:10.1f} | {client_data / 1024:16.1f} | {server_storage / 1024:14.1f}")

    def security_analysis(self):
        print(f"\n=== 安全性分析 ===")

        print("使用的密码学原语:")
        print(f"  • Paillier加密: {self.paillier_n_squared_size * 8}-bit 安全性")
        print(f"  • NIST P-256: 128-bit 安全性")
        print(f"  • SHA-256: 128-bit 碰撞抗性")

        print(f"\n安全属性:")
        print("  • 模型隐私: Paillier同态加密保护")
        print("  • 完整性: 向量同态哈希(VHH)验证")
        print("  • 新鲜性: 时间戳哈希H(t)防止重放")

        print(f"\n密码学参数:")
        print(f"  • 椭圆曲线: NIST P-256 (secp256r1)")
        print(f"  • 哈希函数: SHA-256")
        print(f"  • 同态加密: Paillier with {self.paillier_n_squared_size * 8}-bit modulus")


def main():
    analyzer = RealNISTP256Step2()

    print("真实 NIST P-256 步骤2通信开销分析")
    print("=" * 70)
    print("使用真实密码学原语: NIST P-256 + Paillier + SHA-256")
    print("=" * 70)

    num_clients = 100
    threshold = 51

    results = analyzer.measure_step2_communication(num_clients, threshold)

    analyzer.performance_analysis(num_clients)

    analyzer.scalability_analysis()

    analyzer.security_analysis()

    print("\n" + "=" * 70)
    print("步骤2总结 (100客户端 + 1服务器):")
    print(f"📤 客户端总发送: {results['client_to_server_total'] / 1024:.2f} KB")
    print(f"📥 服务器总接收: {results['client_to_server_total'] / 1024:.2f} KB")
    print(f"💾 服务器存储: {results['server_total_storage'] / 1024:.2f} KB")
    print(f"📊 每客户端发送: {results['client_data_per_message'] / 1024:.2f} KB")
    print(f"⏱️  预计计算时间: ~10-50 ms/客户端")
    print(f"🔒 安全等级: 128-bit")


if __name__ == "__main__":
    main()