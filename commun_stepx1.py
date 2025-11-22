from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import math


class NISTP256ElGamal:

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

    def get_point_size(self, compressed=True):
        private_key = ec.generate_private_key(self.curve, self.backend)
        public_key = private_key.public_key()

        if compressed:
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

    def elgamal_ciphertext_size(self, compressed=True):
        return 2 * self.get_point_size(compressed)


class VSSCommunicationCalculator:

    def __init__(self, n_clients=100, threshold=None, use_compressed_points=True):
        self.n_clients = n_clients
        self.threshold = threshold if threshold else math.ceil(n_clients / 2)
        self.crypto = NISTP256ElGamal()
        self.compressed = use_compressed_points

        self.ec_point_size = self.crypto.get_point_size(use_compressed_points)
        self.elgamal_ciphertext_size = self.crypto.elgamal_ciphertext_size(use_compressed_points)

        self.shares_per_client = n_clients
        self.commitments_per_client = self.threshold

    def calculate_single_client_upload(self):
        commitments_size = self.commitments_per_client * self.ec_point_size


        ciphertexts_size = self.n_clients * self.elgamal_ciphertext_size

        receiver_indices_size = self.n_clients * 4

        total_upload = commitments_size + ciphertexts_size + receiver_indices_size

        return {
            'commitments_size': commitments_size,
            'ciphertexts_size': ciphertexts_size,
            'receiver_indices_size': receiver_indices_size,
            'total_upload': total_upload
        }

    def calculate_total_communication(self):
        single_client = self.calculate_single_client_upload()

        total_upload_all_clients = self.n_clients * single_client['total_upload']

        broadcast_commitments = self.n_clients * self.commitments_per_client * self.ec_point_size

        total_network_traffic = total_upload_all_clients + broadcast_commitments

        return {
            'single_client_upload': single_client,
            'total_upload_all_clients': total_upload_all_clients,
            'broadcast_commitments': broadcast_commitments,
            'total_network_traffic': total_network_traffic
        }

    def print_detailed_analysis(self):

        total = self.calculate_total_communication()
        single = total['single_client_upload']

        print("=" * 60)
        print("VSS通信开销详细分析 (基于NIST P-256和ElGamal加密)")
        print("=" * 60)
        print(f"系统参数:")
        print(f"  • 客户端数量: {self.n_clients}")
        print(f"  • VSS阈值 t: {self.threshold}")
        print(f"  • 椭圆曲线: NIST P-256 (SECP256R1)")
        print(f"  • 点压缩: {'是' if self.compressed else '否'}")
        print(f"  • 曲线点大小: {self.ec_point_size} 字节")
        print(f"  • ElGamal密文大小: {self.elgamal_ciphertext_size} 字节")
        print()

        print("单个客户端上传开销:")
        print(f"  • 承诺列表 ({self.threshold}个承诺): {single['commitments_size']:,} 字节")
        print(f"  • 密文列表 ({self.n_clients}个密文): {single['ciphertexts_size']:,} 字节")
        print(f"  • 接收者索引: {single['receiver_indices_size']:,} 字节")
        print(f"  • 总计: {single['total_upload']:,} 字节")
        print(f"    ≈ {single['total_upload'] / 1024:.2f} KB")
        print()

        print("总体通信开销:")
        print(f"  • 所有客户端上传: {total['total_upload_all_clients']:,} 字节")
        print(f"    ≈ {total['total_upload_all_clients'] / (1024 ** 2):.2f} MB")
        print(f"  • 服务器广播承诺: {total['broadcast_commitments']:,} 字节")
        print(f"    ≈ {total['broadcast_commitments'] / (1024 ** 2):.2f} MB")
        print(f"  • 网络总流量: {total['total_network_traffic']:,} 字节")
        print(f"    ≈ {total['total_network_traffic'] / (1024 ** 2):.2f} MB")
        print()

        if self.compressed:
            uncompressed_calc = VSSCommunicationCalculator(
                n_clients=self.n_clients,
                threshold=self.threshold,
                use_compressed_points=False
            )
            uncompressed_total = uncompressed_calc.calculate_total_communication()
            savings = (uncompressed_total['total_network_traffic'] - total['total_network_traffic']) / \
                      uncompressed_total['total_network_traffic'] * 100
            print(f"使用点压缩节省: {savings:.1f}%")

        print("=" * 60)


def analyze_different_scenarios():
    scenarios = [
        (50, 26),
        (100, 51),
        (200, 101),
        (500, 251)
    ]

    print("不同规模系统的通信开销比较")
    print("=" * 50)

    for n, t in scenarios:
        calculator = VSSCommunicationCalculator(n_clients=n, threshold=t)
        total = calculator.calculate_total_communication()

        print(f"n={n}, t={t}:")
        print(f"  总流量: {total['total_network_traffic'] / (1024 ** 2):.2f} MB")
        print(f"  单客户端: {total['single_client_upload']['total_upload'] / 1024:.2f} KB")


if __name__ == "__main__":
    calculator = VSSCommunicationCalculator(n_clients=100, threshold=51)
    calculator.print_detailed_analysis()

    print("\n")
    analyze_different_scenarios()