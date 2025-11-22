import time
import random
import secrets
from typing import List


class FiniteFieldVHHCalculator:
    """基于有限域的VHH计算器（使用NIST P-256素数）"""

    def __init__(self, dimension: int):
        self.dimension = dimension

        # 使用NIST P-256的素数阶
        self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

        # 生成基向量 g_1, g_2, ..., g_m ∈ GF(p)*
        self.g = [secrets.randbelow(self.p - 1) + 1 for _ in range(dimension)]  # 确保非零

    def compute_vhh_original(self, vector: List[int]) -> int:
        """原始VHH计算: ∏ g_j^{v_j} mod p"""
        start_time = time.time()

        result = 1
        for j in range(self.dimension):
            exponent = vector[j] % (self.p - 1)  # 使用费马小定理
            term = pow(self.g[j], exponent, self.p)  # 模幂运算
            result = (result * term) % self.p  # 模乘法

        elapsed = time.time() - start_time
        return result, elapsed


def generate_test_vector(dimension: int, sparsity: float = 0.1) -> List[int]:
    """生成测试向量"""
    vector = [0] * dimension
    # 只有sparsity比例的元素是非零的
    nonzero_count = int(dimension * sparsity)
    nonzero_indices = random.sample(range(dimension), nonzero_count)

    for idx in nonzero_indices:
        vector[idx] = random.randint(1, 1000)

    return vector


def main():
    """主测试函数"""
    dimension = 100000  # 100k维度
    print(f"测试有限域VHH计算性能")
    print(f"向量维度: {dimension}")
    print(f"有限域: GF(p), p = 2^256 (NIST P-256素数)")
    print("=" * 50)

    # 初始化VHH计算器
    calculator = FiniteFieldVHHCalculator(dimension)

    # 生成测试向量
    test_vector = generate_test_vector(dimension, sparsity=0.1)
    nonzero_count = sum(1 for x in test_vector if x != 0)
    print(f"测试向量: {nonzero_count}/{dimension} 非零元素 ({nonzero_count / dimension * 100:.1f}%)")

    # 测试原始VHH计算
    print("\n原始VHH计算 (计算所有维度):")
    result, time_taken = calculator.compute_vhh_original(test_vector)
    print(f"耗时: {time_taken:.4f}秒")
    print(f"计算速度: {dimension / time_taken:.0f} 元素/秒")
    print(f"单个VHH计算时间: {time_taken:.4f}秒")


if __name__ == "__main__":
    main()