import time
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class EllipticCurveScalarAdditionBenchmark:
    def __init__(self):
        self.curve = ec.SECP256R1()  # NIST P-256曲线
        self.backend = default_backend()

        # 获取曲线参数 - NIST P-256的标准参数
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        print(f"NIST P-256曲线阶: {self.order}")

    def generate_scalars(self, num_scalars: int = 100):
        """生成测试标量（在曲线阶范围内）"""
        print(f"生成 {num_scalars} 个标量...")
        scalars = []
        for i in range(num_scalars):
            # 生成随机标量，在曲线阶范围内
            scalar = random.randint(1, self.order - 1)
            scalars.append(scalar)
        return scalars

    def scalar_addition_naive(self, scalars: list):
        """朴素方法：逐个相加（模曲线阶）"""
        start_time = time.perf_counter()

        result = 0
        for scalar in scalars:
            result = (result + scalar) % self.order

        compute_time = time.perf_counter() - start_time
        return result, compute_time

    def scalar_addition_builtin_sum(self, scalars: list):
        """使用内置sum函数（模曲线阶）"""
        start_time = time.perf_counter()

        total = sum(scalars) % self.order

        compute_time = time.perf_counter() - start_time
        return total, compute_time

    def scalar_addition_accumulate(self, scalars: list):
        """使用累加方法，减少模运算次数"""
        start_time = time.perf_counter()

        result = 0
        for scalar in scalars:
            result += scalar
        result %= self.order

        compute_time = time.perf_counter() - start_time
        return result, compute_time

    def scalar_addition_batch_mod(self, scalars: list, batch_size: int = 10):
        """批量模运算方法"""
        start_time = time.perf_counter()

        result = 0
        for i, scalar in enumerate(scalars):
            result += scalar
            if (i + 1) % batch_size == 0:
                result %= self.order

        result %= self.order
        compute_time = time.perf_counter() - start_time
        return result, compute_time

    def scalar_addition_with_ec_operations(self, scalars: list):
        """包含实际椭圆曲线操作的测试"""
        start_time = time.perf_counter()

        # 生成一个私钥用于测试
        private_key = ec.generate_private_key(self.curve, self.backend)

        # 模拟一些椭圆曲线操作
        public_key = private_key.public_key()

        # 标量加法（主要测试部分）
        scalar_sum = sum(scalars) % self.order

        compute_time = time.perf_counter() - start_time
        return scalar_sum, compute_time

    def verify_results(self, *results):
        """验证所有方法结果一致"""
        return all(r == results[0] for r in results[1:])

    def benchmark_scalar_addition(self, num_scalars: int = 100):
        """基准测试标量加法"""
        print("=" * 70)
        print(f"NIST P-256曲线下{num_scalars}个标量累加时间基准测试")
        print("=" * 70)

        # 生成测试数据
        scalars = self.generate_scalars(num_scalars)
        print(f"数据生成完成，标量范围: 1 到 {self.order - 1}")

        print("\n" + "=" * 70)
        print("方法1: 朴素方法 (逐个模加)")
        print("=" * 70)
        result1, time1 = self.scalar_addition_naive(scalars)
        print(f"计算结果: {result1}")
        print(f"计算时间: {time1:.9f} 秒")
        print(f"处理速度: {num_scalars / time1:,.0f} 标量/秒")
        print(f"平均每个标量: {time1 / num_scalars:.9f} 秒")

        print("\n" + "=" * 70)
        print("方法2: 内置sum函数 (最后模运算)")
        print("=" * 70)
        result2, time2 = self.scalar_addition_builtin_sum(scalars)
        print(f"计算结果: {result2}")
        print(f"计算时间: {time2:.9f} 秒")
        print(f"处理速度: {num_scalars / time2:,.0f} 标量/秒")
        print(f"速度提升: {time1 / time2:.2f}x")

        print("\n" + "=" * 70)
        print("方法3: 累加方法 (减少模运算)")
        print("=" * 70)
        result3, time3 = self.scalar_addition_accumulate(scalars)
        print(f"计算结果: {result3}")
        print(f"计算时间: {time3:.9f} 秒")
        print(f"处理速度: {num_scalars / time3:,.0f} 标量/秒")
        print(f"速度提升: {time1 / time3:.2f}x")

        print("\n" + "=" * 70)
        print("方法4: 批量模运算 (每10次模运算)")
        print("=" * 70)
        result4, time4 = self.scalar_addition_batch_mod(scalars, batch_size=10)
        print(f"计算结果: {result4}")
        print(f"计算时间: {time4:.9f} 秒")
        print(f"处理速度: {num_scalars / time4:,.0f} 标量/秒")
        print(f"速度提升: {time1 / time4:.2f}x")

        print("\n" + "=" * 70)
        print("方法5: 包含EC操作 (参考对比)")
        print("=" * 70)
        result5, time5 = self.scalar_addition_with_ec_operations(scalars)
        print(f"计算结果: {result5}")
        print(f"计算时间: {time5:.9f} 秒")
        print(f"处理速度: {num_scalars / time5:,.0f} 标量/秒")

        # 验证结果一致性
        print("\n" + "=" * 70)
        print("结果验证")
        print("=" * 70)
        consistent = self.verify_results(result1, result2, result3, result4, result5)
        print(f"所有方法结果一致: {consistent}")

        print("\n" + "=" * 70)
        print("性能总结")
        print("=" * 70)

        addition_times = [time1, time2, time3, time4]
        best_time = min(addition_times)
        best_method = addition_times.index(best_time) + 1

        print(f"最佳加法方法: 方法{best_method}")
        print(f"最佳时间: {best_time:.9f} 秒")
        print(f"总处理标量: {num_scalars}")
        print(f"处理速度: {num_scalars / best_time:,.0f} 标量/秒")
        print(f"平均每个标量: {best_time / num_scalars:.9f} 秒")
        print(f"曲线阶: {self.order}")
        print(f"有限域素数: {self.p}")

        # 时间分布
        print(f"\n纯加法方法时间分布:")
        total_addition_time = sum(addition_times)
        for i, t in enumerate(addition_times, 1):
            print(f"  方法{i}: {t:.9f} 秒 ({t / total_addition_time * 100:.1f}%)")

        return {
            'naive_time': time1,
            'builtin_time': time2,
            'accumulate_time': time3,
            'batch_time': time4,
            'ec_operations_time': time5,
            'best_time': best_time,
            'total_scalars': num_scalars,
            'scalars_per_second': num_scalars / best_time,
            'results_consistent': consistent,
            'final_result': result1,
            'curve_order': self.order,
            'field_prime': self.p
        }

    def benchmark_different_sizes(self):
        """测试不同数量的标量加法"""
        print("\n" + "=" * 70)
        print("不同数量标量加法性能测试 (NIST P-256)")
        print("=" * 70)

        sizes = [10, 50, 100, 500, 1000, 5000, 10000]

        results = []

        for num_scalars in sizes:
            print(f"\n测试规模: {num_scalars}个标量")
            print("-" * 50)

            scalars = self.generate_scalars(num_scalars)

            # 使用最佳方法（内置sum）
            start_time = time.perf_counter()
            result = sum(scalars) % self.order
            compute_time = time.perf_counter() - start_time

            speed = num_scalars / compute_time

            print(f"计算时间: {compute_time:.9f} 秒")
            print(f"处理速度: {speed:,.0f} 标量/秒")
            print(f"结果: {result}")

            results.append({
                'num_scalars': num_scalars,
                'time': compute_time,
                'speed': speed,
                'result': result
            })

        # 总结不同规模的性能
        print("\n" + "=" * 70)
        print("规模性能总结")
        print("=" * 70)

        for result in results:
            print(f"{result['num_scalars']:5d}个标量: "
                  f"{result['time']:12.9f}秒, {result['speed']:12,.0f}标量/秒")


def main():
    benchmark = EllipticCurveScalarAdditionBenchmark()

    # 主要基准测试
    print("主要基准测试: NIST P-256曲线下100个标量累加")
    results = benchmark.benchmark_scalar_addition(num_scalars=100)

    # 不同规模测试
    benchmark.benchmark_different_sizes()

    print("\n" + "=" * 70)
    print("最终结论")
    print("=" * 70)
    print(f"NIST P-256曲线下100个标量累加:")
    print(f"  - 总标量数: {results['total_scalars']}")
    print(f"  - 最佳时间: {results['best_time']:.9f} 秒")
    print(f"  - 处理速度: {results['scalars_per_second']:,.0f} 标量/秒")
    print(f"  - 每个标量: {results['best_time'] / 100:.9f} 秒")
    print(f"  - 曲线阶: {results['curve_order']}")
    print(f"  - 有限域素数: {results['field_prime']}")
    print(f"  - 最终结果: {results['final_result']}")
    print(f"  - 包含EC操作时间: {results['ec_operations_time']:.9f} 秒")


if __name__ == "__main__":
    main()