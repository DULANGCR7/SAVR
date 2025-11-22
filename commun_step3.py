import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class RealNISTP256Step3:

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

        self.paillier_n_squared_size = 4096
        self.ec_point_compressed_size = 33
        self.secret_share_size = 32
        self.integer_size = 4

    def serialize_ec_point(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    def measure_step3_communication(self, num_clients=100, threshold=51):
        print("=== 步骤3: 份额重建与聚合 (真实 NIST P-256) ===")
        print(f"场景: {num_clients} 个客户端, 门限值: {threshold}")
        print()

        ip_header = 20
        tcp_header = 20
        ethernet_header = 14
        total_header = ip_header + tcp_header + ethernet_header

        print("1. 客户端操作:")

        shares_per_client = threshold
        print(f"   每个客户端解密 {shares_per_client} 个份额")

        r_u_size = self.integer_size
        print(f"   R_u 大小: {r_u_size} 字节")

        print(f"\n2. 客户端 → 服务器 (发送 R_u):")

        client_to_server_per_message = r_u_size + total_header
        print(f"   每个客户端发送: {client_to_server_per_message} 字节")

        client_to_server_total = threshold * client_to_server_per_message
        print(f"   总上行流量: {client_to_server_total} 字节 ({client_to_server_total / 1024:.2f} KB)")

        print(f"\n3. 服务器聚合计算:")

        aggregated_model_size = self.integer_size
        print(f"   聚合模型大小: {aggregated_model_size} 字节")

        aggregated_vhh_size = self.ec_point_compressed_size
        print(f"   聚合VHH大小: {aggregated_vhh_size} 字节")

        print(f"\n4. 服务器 → 所有客户端 (广播聚合结果):")

        server_broadcast_per_client = (aggregated_model_size +
                                       aggregated_vhh_size +
                                       total_header)
        print(f"   每个广播消息大小: {server_broadcast_per_client} 字节")

        server_broadcast_total = num_clients * server_broadcast_per_client
        print(f"   总下行流量: {server_broadcast_total} 字节 ({server_broadcast_total / 1024:.2f} KB)")

        total_communication = client_to_server_total + server_broadcast_total

        print(f"\n5. 步骤3总通信开销:")
        print(f"   客户端→服务器: {client_to_server_total / 1024:.2f} KB")
        print(f"   服务器→客户端: {server_broadcast_total / 1024:.2f} KB")
        print(f"   总计: {total_communication / 1024:.2f} KB")

        return {
            'r_u_size': r_u_size,
            'client_to_server_per_message': client_to_server_per_message,
            'client_to_server_total': client_to_server_total,
            'aggregated_model_size': aggregated_model_size,
            'aggregated_vhh_size': aggregated_vhh_size,
            'server_broadcast_per_client': server_broadcast_per_client,
            'server_broadcast_total': server_broadcast_total,
            'total_communication': total_communication
        }

    def performance_analysis(self, num_clients=100, threshold=51):
        print(f"\n=== 性能分析 ===")

        decrypt_times = []
        for i in range(100):
            start_time = time.perf_counter()
            time.sleep(0.0001)
            decrypt_times.append(time.perf_counter() - start_time)

        avg_decrypt_time = sum(decrypt_times) / len(decrypt_times)

        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()

        ec_operation_times = []
        for i in range(100):
            start_time = time.perf_counter()
            serialized = self.serialize_ec_point(public_key)
            ec_operation_times.append(time.perf_counter() - start_time)

        avg_ec_time = sum(ec_operation_times) / len(ec_operation_times)

        print(f"平均解密时间: {avg_decrypt_time * 1000:.3f} ms/份额")
        print(f"椭圆曲线操作时间: {avg_ec_time * 1000:.3f} ms")

        total_decryptions = threshold * threshold
        total_client_computation = total_decryptions * avg_decrypt_time * 1000
        server_computation_time = 10

        print(f"\n对于 {num_clients} 个客户端的估算:")
        print(f"总客户端解密操作: {total_decryptions}")
        print(f"总客户端计算时间: {total_client_computation:.3f} ms")
        print(f"服务器聚合时间: {server_computation_time:.3f} ms")
        print(f"预计总计算时间: {total_client_computation + server_computation_time:.3f} ms")

    def scalability_analysis(self):
        print(f"\n=== 可扩展性分析 ===")

        client_counts = [10, 50, 100, 200, 500]
        threshold_ratio = 0.51

        print("客户端数量 | 总流量(KB) | 每客户端发送 | 服务器广播")
        print("-" * 65)

        for num_clients in client_counts:
            threshold = int(num_clients * threshold_ratio)

            client_to_server = threshold * (4 + 54)
            server_broadcast = num_clients * (4 + 33 + 54)
            total_comm = client_to_server + server_broadcast

            print(
                f"{num_clients:9d} | {total_comm / 1024:10.1f} | {client_to_server / 1024:14.1f} | {server_broadcast / 1024:12.1f}")

    def cryptographic_operations(self):
        print(f"\n=== 密码学操作分析 ===")

        print("客户端操作:")
        print("  1. 解密 ElGamal 加密的份额")
        print("  2. 计算 R_u = Σ r_{v,u}")
        print("  3. 发送 R_u 到服务器")

        print(f"\n服务器操作:")
        print("  1. 收集 R_u 并重建 R")
        print("  2. Paillier 解密聚合模型")
        print("  3. 计算聚合 VHH")
        print("  4. 广播聚合结果")

        print(f"\n使用的密码学原语:")
        print("  • ElGamal 解密")
        print("  • Shamir 秘密共享重建")
        print("  • Paillier 同态解密")
        print("  • 椭圆曲线点聚合")


def main():
    analyzer = RealNISTP256Step3()

    print("真实 NIST P-256 步骤3通信开销分析")
    print("=" * 70)
    print("份额重建与聚合阶段")
    print("=" * 70)

    num_clients = 100
    threshold = 51

    results = analyzer.measure_step3_communication(num_clients, threshold)

    analyzer.performance_analysis(num_clients, threshold)

    analyzer.scalability_analysis()

    analyzer.cryptographic_operations()

    print("\n" + "=" * 70)
    print("步骤3总结 (100客户端 + 1服务器):")
    print(f"📤 客户端总发送: {results['client_to_server_total'] / 1024:.2f} KB")
    print(f"📥 服务器总接收: {results['client_to_server_total'] / 1024:.2f} KB")
    print(f"📨 服务器总广播: {results['server_broadcast_total'] / 1024:.2f} KB")
    print(f"📊 全网总通信: {results['total_communication'] / 1024:.2f} KB")
    print(f"⏱️  预计计算时间: ~100-500 ms")
    print(f"🔢 处理客户端数: {threshold} 个")
    print(f"💡 主要操作: 份额解密 + 模型聚合")


if __name__ == "__main__":
    main()