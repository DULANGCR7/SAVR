from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import math


class NISTP256Communication:

    def __init__(self, use_compressed=True):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()
        self.compressed = use_compressed

    def get_point_size(self):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()

        if self.compressed:
            point_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )
        else:
            point_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

        return len(point_bytes)

    def get_scalar_size(self):
        return 32


class StepIICommunicationAnalyzer:

    def __init__(self, n_clients=100, threshold=51, subset_size=None):
        self.n_clients = n_clients
        self.threshold = threshold
        self.subset_size = subset_size if subset_size else threshold

        self.crypto = NISTP256Communication(use_compressed=True)

        self.ec_point_size = self.crypto.get_point_size()
        self.scalar_size = self.crypto.get_scalar_size()

    def analyze_client_communication(self):
        print("=" * 60)
        print("Step II 客户端通信开销分析")
        print("=" * 60)

        print("1. 解密操作 (本地):")
        print(f"   • 每个客户端解密 {self.subset_size} 个密文")
        print(f"   • 获得 {self.subset_size} 个 (r_{{v,u}}^(t), o_{{v,u}}^(t)) 对")
        print("   → 无网络通信开销")
        print()

        print("2. 本地聚合计算:")
        print(f"   • 计算 R_u^(t) = Σ r_{{v,u}}^(t) (v∈U₃)")
        print(f"   • 计算 O_u^(t) = Σ o_{{v,u}}^(t) (v∈U₃)")
        print("   → 无网络通信开销")
        print()

        print("3. 上传聚合值到服务器:")
        upload_per_client = 2 * self.scalar_size

        print(f"   • 每个客户端发送: R_u^(t) + O_u^(t)")
        print(f"   • 每个标量大小: {self.scalar_size} 字节")
        print(f"   • 单客户端上传: {upload_per_client} 字节")
        print(f"     ≈ {upload_per_client / 1024:.2f} KB")
        print()

        total_client_upload = self.n_clients * upload_per_client

        return {
            'upload_per_client': upload_per_client,
            'total_client_upload': total_client_upload,
            'clients_count': self.n_clients
        }

    def analyze_server_communication(self):
        print("=" * 60)
        print("Step II 服务器通信开销分析")
        print("=" * 60)

        print("1. 接收客户端数据:")
        receive_from_clients = self.n_clients * 2 * self.scalar_size
        print(f"   • 接收 {self.n_clients} 个客户端的 (R_u^(t), O_u^(t))")
        print(f"   • 总接收数据: {receive_from_clients:,} 字节")
        print(f"     ≈ {receive_from_clients / 1024:.2f} KB")
        print()

        print("2. VSS重建操作 (本地):")
        print(f"   • 执行 VSS.Rec(t, {{R_u^(t), O_u^(t)}}_{{u∈U₃}})")
        print(f"   • 使用 {self.subset_size} 个份额重建秘密")
        print("   → 无网络通信开销")
        print()

        print("3. Pedersen承诺验证:")
        print("   • 计算: Π (g^? h^?) =? g^R^(t) h^O^(t)")
        print("   • 涉及椭圆曲线点运算")
        print("   → 无网络通信开销")
        print()

        print("4. 聚合结果计算:")
        print("   • 计算: Σ x_u^(t) 和 Π VHH(x_u^(t))")
        print("   → 无网络通信开销")
        print()

        total_server_communication = receive_from_clients

        return {
            'receive_from_clients': receive_from_clients,
            'total_server_communication': total_server_communication
        }

    def analyze_network_traffic(self):
        client_analysis = self.analyze_client_communication()
        server_analysis = self.analyze_server_communication()

        print("=" * 60)
        print("Step II 总体网络流量分析")
        print("=" * 60)

        total_network_traffic = client_analysis['total_client_upload']

        print(f"网络总流量: {total_network_traffic:,} 字节")
        print(f"            ≈ {total_network_traffic / 1024:.2f} KB")
        print(f"            ≈ {total_network_traffic / (1024 ** 2):.2f} MB")
        print()

        print("流量分布:")
        print(f"  • 客户端 → 服务器: {total_network_traffic:,} 字节 (100%)")
        print(f"  • 服务器 → 客户端: 0 字节 (0%)")
        print()

        return {
            'total_network_traffic': total_network_traffic,
            'client_analysis': client_analysis,
            'server_analysis': server_analysis
        }

    def compare_with_step_i(self):
        step_i_approx = 1_036_600

        current_analysis = self.analyze_network_traffic()
        step_ii_traffic = current_analysis['total_network_traffic']

        reduction = (step_i_approx - step_ii_traffic) / step_i_approx * 100

        print("=" * 60)
        print("与 Step I 的通信开销比较")
        print("=" * 60)
        print(f"Step I 总流量: {step_i_approx:,} 字节 ≈ {step_i_approx / (1024 ** 2):.2f} MB")
        print(f"Step II 总流量: {step_ii_traffic:,} 字节 ≈ {step_ii_traffic / (1024 ** 2):.2f} MB")
        print(f"通信开销减少: {reduction:.1f}%")
        print()

        print("原因分析:")
        print("1. Step II 只传输聚合的标量值，而非ElGamal密文")
        print("2. 每个客户端只发送 64 字节，而非 8.5 KB")
        print("3. 没有大量的承诺和密文传输")


def analyze_different_scenarios():
    scenarios = [
        (50, 26),
        (100, 51),
        (200, 101),
        (500, 251)
    ]

    print("不同规模系统的Step II通信开销")
    print("=" * 50)

    for n, t in scenarios:
        analyzer = StepIICommunicationAnalyzer(n_clients=n, threshold=t)
        analysis = analyzer.analyze_network_traffic()

        traffic_kb = analysis['total_network_traffic'] / 1024
        per_client = analysis['client_analysis']['upload_per_client']

        print(f"n={n:3d}, t={t:3d}: 总流量={traffic_kb:6.1f} KB, 单客户端={per_client} 字节")


if __name__ == "__main__":
    analyzer = StepIICommunicationAnalyzer(n_clients=100, threshold=51)

    print("NIST P-256椭圆曲线参数:")
    print(f"  • 压缩点大小: {analyzer.ec_point_size} 字节")
    print(f"  • 标量大小: {analyzer.scalar_size} 字节")
    print(f"  • 子集U₃大小: {analyzer.subset_size} 客户端")
    print()

    analyzer.analyze_network_traffic()

    print("\n")
    analyzer.compare_with_step_i()

    print("\n")
    analyze_different_scenarios()