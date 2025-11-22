from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class NISTP256Analyzer:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()
        self.ec_point_size = 33
        self.scalar_size = 32

    def analyze_step_x(self, n_clients=100, threshold=51, error_rate=0.1):
        failed_clients = max(1, int(n_clients * error_rate))
        subset_size = threshold

        commitments_per_client = subset_size * threshold * self.ec_point_size
        indices_per_client = subset_size * 4
        server_send_commitments = failed_clients * (commitments_per_client + indices_per_client)

        proof_size = 2 * self.scalar_size + 2 * self.ec_point_size + self.scalar_size + 4
        server_receive_proofs = failed_clients * proof_size

        server_broadcast = n_clients * 4

        server_total = server_send_commitments + server_receive_proofs + server_broadcast

        failed_client_receive = commitments_per_client + indices_per_client

        failed_client_send = proof_size

        all_client_receive_broadcast = n_clients * 4

        failed_client_total = failed_client_receive + failed_client_send + all_client_receive_broadcast
        normal_client_total = all_client_receive_broadcast

        client_network_total = (failed_clients * (failed_client_receive + failed_client_send) +
                                n_clients * all_client_receive_broadcast)

        return {
            'error_rate': error_rate,
            'failed_clients': failed_clients,
            'normal_clients': n_clients - failed_clients,

            'server_total_bytes': server_total,
            'server_total_mb': server_total / (1024 * 1024),

            'client_total_bytes': client_network_total,
            'client_total_kb': client_network_total / 1024,

            'failed_client_individual_bytes': failed_client_total,
            'normal_client_individual_bytes': normal_client_total,

            'server_send_commitments_mb': server_send_commitments / (1024 * 1024),
            'server_receive_proofs_kb': server_receive_proofs / 1024,
            'server_broadcast_bytes': server_broadcast,

            'client_receive_commitments_kb': (failed_clients * failed_client_receive) / 1024,
            'client_send_proofs_kb': (failed_clients * failed_client_send) / 1024,
            'client_receive_broadcast_bytes': n_clients * all_client_receive_broadcast
        }


def main():
    analyzer = NISTP256Analyzer()

    print("Step x 完整通信开销分析 (100客户端, NIST P-256)")
    print("=" * 80)
    print(
        f"{'错误率':<8} {'失败客户端':<12} {'服务器总开销':<15} {'客户端总开销':<15} {'失败客户端个体':<15} {'正常客户端个体':<15}")
    print(f"{'':<8} {'':<12} {'(MB)':<15} {'(KB)':<15} {'(KB)':<15} {'(字节)':<15}")
    print("-" * 80)

    for error_rate in [0.1, 0.2, 0.3]:
        result = analyzer.analyze_step_x(error_rate=error_rate)

        print(f"{error_rate * 100:>2.0f}%    "
              f"{result['failed_clients']:>6}      "
              f"{result['server_total_mb']:>8.2f} MB    "
              f"{result['client_total_kb']:>8.2f} KB    "
              f"{result['failed_client_individual_bytes'] / 1024:>8.2f} KB    "
              f"{result['normal_client_individual_bytes']:>8} 字节")

    print("\n" + "=" * 80)
    print("详细开销分解 (以10%错误率为例):")
    result_10 = analyzer.analyze_step_x(error_rate=0.1)
    print(f"服务器开销分解:")
    print(
        f"  • 发送承诺列表: {result_10['server_send_commitments_mb']:.2f} MB ({result_10['server_send_commitments_mb'] / result_10['server_total_mb'] * 100:.1f}%)")
    print(
        f"  • 接收解密证明: {result_10['server_receive_proofs_kb']:.2f} KB ({result_10['server_receive_proofs_kb'] * 1024 / result_10['server_total_bytes'] * 100:.1f}%)")
    print(
        f"  • 广播更新列表: {result_10['server_broadcast_bytes']} 字节 ({result_10['server_broadcast_bytes'] / result_10['server_total_bytes'] * 100:.1f}%)")

    print(f"\n客户端开销分解:")
    print(f"  • 接收承诺列表: {result_10['client_receive_commitments_kb']:.2f} KB")
    print(f"  • 发送解密证明: {result_10['client_send_proofs_kb']:.2f} KB")
    print(f"  • 接收广播: {result_10['client_receive_broadcast_bytes']} 字节")


if __name__ == "__main__":
    main()