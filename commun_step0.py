import time
import math
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets


class RealNISTP256Communication:

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

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

    def measure_actual_sizes(self):
        print("=== 实际 NIST P-256 数据大小测量 ===")

        private_key, public_key = self.generate_key_pair()

        compressed_pk = self.serialize_public_key(public_key, compressed=True)
        uncompressed_pk = self.serialize_public_key(public_key, compressed=False)

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        print(f"压缩公钥大小: {len(compressed_pk)} 字节")
        print(f"未压缩公钥大小: {len(uncompressed_pk)} 字节")
        print(f"私钥大小 (DER编码): {len(private_key_bytes)} 字节")
        print(f"私钥大小 (原始): 32 字节")

        return {
            'compressed_pk_size': len(compressed_pk),
            'uncompressed_pk_size': len(uncompressed_pk),
            'private_key_size': len(private_key_bytes)
        }

    def client_key_generation_phase(self, num_clients=100, use_compressed=True):
        print(f"\n=== 步骤 0: 密钥生成与广播 (真实 NIST P-256) ===")
        print(f"场景: {num_clients} 个客户端 + 1 个服务器")

        sizes = self.measure_actual_sizes()
        pk_size = sizes['compressed_pk_size'] if use_compressed else sizes['uncompressed_pk_size']

        ip_header = 20  # bytes
        tcp_header = 20  # bytes
        ethernet_header = 14  # bytes
        total_header = ip_header + tcp_header + ethernet_header

        print(f"\n网络协议头大小:")
        print(f"  IP头: {ip_header} 字节")
        print(f"  TCP头: {tcp_header} 字节")
        print(f"  以太网头: {ethernet_header} 字节")
        print(f"  总头大小: {total_header} 字节")

        client_to_server_per_msg = pk_size + total_header
        client_to_server_total = num_clients * client_to_server_per_msg

        print(f"\n1. 客户端 → 服务器 (发送公钥):")
        print(f"   每个公钥大小: {pk_size} 字节")
        print(f"   每个消息大小: {client_to_server_per_msg} 字节")
        print(f"   总消息数量: {num_clients}")
        print(f"   总上行流量: {client_to_server_total} 字节 ({client_to_server_total / 1024:.2f} KB)")

        server_broadcast_per_client = num_clients * pk_size + total_header
        server_broadcast_total = num_clients * server_broadcast_per_client

        print(f"\n2. 服务器 → 所有客户端 (广播公钥列表):")
        print(f"   每个广播消息大小: {server_broadcast_per_client} 字节")
        print(f"   广播消息数量: {num_clients}")
        print(f"   总下行流量: {server_broadcast_total} 字节 ({server_broadcast_total / 1024:.2f} KB)")
        print(f"   每个客户端接收: {server_broadcast_per_client} 字节 ({server_broadcast_per_client / 1024:.2f} KB)")

        total_communication = client_to_server_total + server_broadcast_total

        print(f"\n3. 总通信开销:")
        print(f"   总上行流量: {client_to_server_total} 字节 ({client_to_server_total / 1024:.2f} KB)")
        print(f"   总下行流量: {server_broadcast_total} 字节 ({server_broadcast_total / 1024:.2f} KB)")
        print(f"   总流量: {total_communication} 字节 ({total_communication / 1024:.2f} KB)")
        print(f"   平均每个客户端: {total_communication / num_clients:.0f} 字节")

        return {
            'pk_size': pk_size,
            'header_size': total_header,
            'client_to_server_per_msg': client_to_server_per_msg,
            'client_to_server_total': client_to_server_total,
            'server_broadcast_per_client': server_broadcast_per_client,
            'server_broadcast_total': server_broadcast_total,
            'total_communication': total_communication
        }

    def performance_benchmark(self, num_clients=100):
        print(f"\n=== 真实性能基准测试 ===")

        print("测量密钥生成性能...")
        keygen_times = []
        for i in range(10):  # 测试10次取平均
            start_time = time.perf_counter()
            private_key, public_key = self.generate_key_pair()
            keygen_time = time.perf_counter() - start_time
            keygen_times.append(keygen_time)

        avg_keygen_time = sum(keygen_times) / len(keygen_times)
        print(f"平均密钥生成时间: {avg_keygen_time * 1000:.3f} ms")

        print("测量序列化性能...")
        _, public_key = self.generate_key_pair()

        serialize_times_compressed = []
        serialize_times_uncompressed = []

        for i in range(100):
            start_time = time.perf_counter()
            compressed_data = self.serialize_public_key(public_key, compressed=True)
            serialize_times_compressed.append(time.perf_counter() - start_time)

            start_time = time.perf_counter()
            uncompressed_data = self.serialize_public_key(public_key, compressed=False)
            serialize_times_uncompressed.append(time.perf_counter() - start_time)

        avg_serialize_compressed = sum(serialize_times_compressed) / len(serialize_times_compressed)
        avg_serialize_uncompressed = sum(serialize_times_uncompressed) / len(serialize_times_uncompressed)

        print(f"压缩序列化平均时间: {avg_serialize_compressed * 1000:.3f} ms")
        print(f"未压缩序列化平均时间: {avg_serialize_uncompressed * 1000:.3f} ms")

        total_keygen_time = num_clients * avg_keygen_time
        total_serialize_time = num_clients * avg_serialize_compressed

        print(f"\n对于 {num_clients} 个客户端的估算:")
        print(f"总密钥生成时间: {total_keygen_time:.3f} 秒")
        print(f"总序列化时间: {total_serialize_time:.3f} 秒")
        print(f"预计总处理时间: {total_keygen_time + total_serialize_time:.3f} 秒")

    def compare_formats(self, num_clients=100):
        print(f"\n=== 格式比较分析 ===")

        compressed_results = self.client_key_generation_phase(num_clients, use_compressed=True)

        uncompressed_results = self.client_key_generation_phase(num_clients, use_compressed=False)

        print(f"\n=== 格式比较总结 ===")
        print(f"项目                | 压缩格式    | 未压缩格式  | 节省")
        print(f"--------------------|-------------|-------------|---------")
        print(
            f"公钥大小           | {compressed_results['pk_size']:3d} 字节   | {uncompressed_results['pk_size']:3d} 字节   | {uncompressed_results['pk_size'] - compressed_results['pk_size']:2d} 字节")
        print(
            f"客户端→服务器总流量 | {compressed_results['client_to_server_total'] / 1024:5.1f} KB | {uncompressed_results['client_to_server_total'] / 1024:5.1f} KB | {(1 - compressed_results['client_to_server_total'] / uncompressed_results['client_to_server_total']) * 100:3.1f}%")
        print(
            f"服务器广播总流量   | {compressed_results['server_broadcast_total'] / 1024:5.1f} KB | {uncompressed_results['server_broadcast_total'] / 1024:5.1f} KB | {(1 - compressed_results['server_broadcast_total'] / uncompressed_results['server_broadcast_total']) * 100:3.1f}%")
        print(
            f"总通信开销         | {compressed_results['total_communication'] / 1024:5.1f} KB | {uncompressed_results['total_communication'] / 1024:5.1f} KB | {(1 - compressed_results['total_communication'] / uncompressed_results['total_communication']) * 100:3.1f}%")

    def scalability_analysis(self):
        print(f"\n=== 可扩展性分析 ===")

        client_counts = [10, 50, 100, 200, 500]

        print("客户端数量 | 总流量(KB) | 每客户端流量(KB) | 广播消息大小(KB)")
        print("-" * 70)

        for num_clients in client_counts:
            sizes = self.measure_actual_sizes()
            pk_size = sizes['compressed_pk_size']
            header_size = 54

            client_to_server_total = num_clients * (pk_size + header_size)
            server_broadcast_per_client = num_clients * pk_size + header_size
            server_broadcast_total = num_clients * server_broadcast_per_client
            total_communication = client_to_server_total + server_broadcast_total

            print(
                f"{num_clients:9d} | {total_communication / 1024:10.1f} | {total_communication / num_clients / 1024:16.1f} | {server_broadcast_per_client / 1024:17.1f}")

    def practical_considerations(self):
        print(f"\n=== 实际部署考虑 ===")

        print("1. 内存使用:")
        sizes = self.measure_actual_sizes()
        memory_per_client = sizes['compressed_pk_size'] + sizes['private_key_size']
        print(f"   每个客户端内存: ~{memory_per_client} 字节")
        print(f"   100个客户端服务器内存: ~{100 * 33} 字节 (仅公钥存储)")

        print("\n2. 计算开销:")
        print("   密钥生成: ~0.1-1 ms/客户端")
        print("   序列化: ~0.01-0.1 ms/客户端")

        print("\n3. 网络考虑:")
        print("   TCP连接建立: 3次握手，额外开销")
        print("   数据包分片: 大广播消息可能分片")
        print("   网络拥塞: 大量并发连接")

        print("\n4. 安全考虑:")
        print("   使用TLS加密传输")
        print("   验证公钥真实性")
        print("   防止重放攻击")


def main():
    analyzer = RealNISTP256Communication()

    print("真实 NIST P-256 椭圆曲线通信开销分析")
    print("=" * 60)
    print("使用 cryptography 库的实际实现")
    print("=" * 60)

    num_clients = 100

    analyzer.client_key_generation_phase(num_clients, use_compressed=True)

    analyzer.performance_benchmark(num_clients)

    analyzer.compare_formats(num_clients)

    analyzer.scalability_analysis()

    analyzer.practical_considerations()

    print("\n" + "=" * 60)
    print("真实 NIST P-256 实现总结:")
    print("- 压缩公钥: 33 字节")
    print("- 未压缩公钥: 65 字节")
    print("- 对于100客户端，总通信开销: ~332 KB")
    print("- 使用压缩格式节省约 49% 带宽")
    print("- 密钥生成是主要计算开销")


if __name__ == "__main__":
    main()