import time
import random
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import secrets


class EllipticCurveAdditionBenchmarkP256:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.backend = default_backend()

        # NIST P-256 曲线参数
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
        self.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

        # 生成两个不同的生成元 g 和 h
        self.g = self._get_generator()
        self.h = self._get_alternative_generator()

    def _mod_inverse(self, a: int, m: int) -> int:
        """模逆元计算"""
        return pow(a, m - 2, m)

    def _get_generator(self):
        """获取曲线生成元G"""
        # NIST P-256 标准生成元
        g_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        g_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        return ec.EllipticCurvePublicNumbers(g_x, g_y, self.curve).public_key(self.backend)

    def _get_alternative_generator(self):
        """获取另一个生成元h"""
        # 通过将标准生成元乘以一个随机标量来获得不同的生成元
        random_scalar = secrets.randbelow(self.order - 1) + 1
        return self._point_multiply(self.g, random_scalar)

    def _point_multiply(self, point, scalar: int):
        """椭圆曲线标量乘法（double-and-add算法）"""
        if scalar == 0 or point is None:
            return None

        if scalar < 0:
            scalar = scalar % self.order
            if scalar == 0:
                return None

        result = None
        current = point
        k = scalar

        while k > 0:
            if k & 1:
                result = self._point_add(result, current)
            current = self._point_add(current, current)
            k >>= 1

        return result

    def _point_add(self, point1, point2):
        """椭圆曲线点加法"""
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        nums1 = point1.public_numbers()
        nums2 = point2.public_numbers()
        x1, y1 = nums1.x, nums1.y
        x2, y2 = nums2.x, nums2.y

        # 检查点是否相同
        if x1 == x2:
            if y1 == y2:
                # 点加倍 (P + P = 2P)
                if y1 == 0:
                    return None
                s_numerator = (3 * x1 * x1 + self.a) % self.p
                s_denominator = (2 * y1) % self.p
                s_denominator_inv = self._mod_inverse(s_denominator, self.p)
                s = (s_numerator * s_denominator_inv) % self.p
            else:
                # 点互为逆元 (P + (-P) = O)
                return None
        else:
            # 点相加 (P + Q)
            s_numerator = (y2 - y1) % self.p
            s_denominator = (x2 - x1) % self.p
            s_denominator_inv = self._mod_inverse(s_denominator, self.p)
            s = (s_numerator * s_denominator_inv) % self.p

        # 计算新点的坐标
        x3 = (s * s - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        try:
            return ec.EllipticCurvePublicNumbers(x3, y3, self.curve).public_key(self.backend)
        except Exception:
            return None

    def generate_test_points(self, count: int = 100):
        """生成测试点（通过标量乘法生成）"""
        print(f"生成 {count} 个测试点...")
        points = []
        for i in range(count):
            scalar = secrets.randbelow(self.order - 1) + 1
            point = self._point_multiply(self.g, scalar)
            points.append(point)
        print("测试点生成完成")
        return points

    def benchmark_left_side_addition(self, points: list):
        """基准测试左边：100个点的累加"""
        print("开始计算左边：100个点的累加...")
        start_time = time.time()

        # 初始化为第一个点
        result = points[0]

        for i in range(1, len(points)):
            if i % 20 == 0:
                print(f"处理第 {i + 1}/{len(points)} 个点加法...")

            # 点加法：result = result + points[i]
            result = self._point_add(result, points[i])

        compute_time = time.time() - start_time
        print(f"左边计算完成，耗时: {compute_time:.6f}秒")
        return result, compute_time

    def benchmark_right_side(self, R: int, O: int):
        """基准测试右边：计算 g^R + h^O"""
        print("开始计算右边：g^R + h^O...")
        start_time = time.time()

        # 计算 g^R
        g_R = self._point_multiply(self.g, R)

        # 计算 h^O
        h_O = self._point_multiply(self.h, O)

        # 点加法：g^R + h^O
        result = self._point_add(g_R, h_O)

        compute_time = time.time() - start_time
        print(f"右边计算完成，耗时: {compute_time:.6f}秒")
        return result, compute_time

    def benchmark_single_addition(self):
        """基准测试单次点加法"""
        print("基准测试单次点加法...")

        # 生成两个随机点
        scalar1 = secrets.randbelow(self.order - 1) + 1
        scalar2 = secrets.randbelow(self.order - 1) + 1
        point1 = self._point_multiply(self.g, scalar1)
        point2 = self._point_multiply(self.g, scalar2)

        start_time = time.time()
        result = self._point_add(point1, point2)
        compute_time = time.time() - start_time

        print(f"单次点加法完成，耗时: {compute_time:.9f}秒")
        return result, compute_time

    def benchmark_single_multiplication(self):
        """基准测试单次标量乘法"""
        print("基准测试单次标量乘法...")

        scalar = secrets.randbelow(self.order - 1) + 1
        start_time = time.time()
        result = self._point_multiply(self.g, scalar)
        compute_time = time.time() - start_time

        print(f"单次标量乘法完成，耗时: {compute_time:.9f}秒")
        return result, compute_time

    def run_comprehensive_benchmark(self):
        """运行全面的基准测试"""
        print("=" * 80)
        print("NIST P-256 椭圆曲线运算基准测试")
        print("=" * 80)
        print(f"曲线参数:")
        print(f"  - 曲线: NIST P-256")
        print(f"  - 曲线阶: {self.order}")
        print(f"  - 有限域素数: {self.p}")

        # 生成测试数据
        points = self.generate_test_points(100)
        R = secrets.randbelow(self.order - 1) + 1
        O = secrets.randbelow(self.order - 1) + 1

        print(f"\n测试配置:")
        print(f"  - 左边: 100个点的累加")
        print(f"  - 右边: g^R + h^O (R, O为标量)")

        # 测试1: 基本操作基准
        print("\n" + "=" * 80)
        print("测试1: 基本操作性能")
        print("=" * 80)

        # 单次点加法
        _, add_time = self.benchmark_single_addition()
        print(f"单次点加法:")
        print(f"  时间: {add_time:.9f} 秒")
        print(f"  吞吐量: {1 / add_time:.2f} 次/秒")

        # 单次标量乘法
        _, mult_time = self.benchmark_single_multiplication()
        print(f"单次标量乘法:")
        print(f"  时间: {mult_time:.9f} 秒")
        print(f"  吞吐量: {1 / mult_time:.2f} 次/秒")
        print(f"  乘法/加法时间比: {mult_time / add_time:.2f}:1")

        # 测试2: 左边基准测试（100次点加法）
        print("\n" + "=" * 80)
        print("测试2: 左边性能 - 100个点的累加")
        print("=" * 80)

        left_result, left_time = self.benchmark_left_side_addition(points)
        print(f"左边计算性能:")
        print(f"  总时间: {left_time:.6f} 秒")
        print(f"  点加法次数: 99次")
        print(f"  吞吐量: {99 / left_time:.2f} 次加法/秒")
        print(f"  平均每次加法: {left_time / 99:.9f} 秒")

        # 测试3: 右边基准测试（g^R + h^O）
        print("\n" + "=" * 80)
        print("测试3: 右边性能 - g^R + h^O")
        print("=" * 80)

        right_result, right_time = self.benchmark_right_side(R, O)
        print(f"右边计算性能:")
        print(f"  总时间: {right_time:.6f} 秒")
        print(f"  标量乘法次数: 2次")
        print(f"  点加法次数: 1次")
        print(f"  总操作数: 3次")
        print(f"  吞吐量: {1 / right_time:.2f} 次/秒")

        # 性能对比分析
        print("\n" + "=" * 80)
        print("性能对比分析")
        print("=" * 80)

        print(f"操作统计:")
        print(f"  - 左边: 99次点加法")
        print(f"  - 右边: 2次标量乘法 + 1次点加法")

        print(f"\n时间对比:")
        print(f"  - 左边总时间: {left_time:.6f} 秒")
        print(f"  - 右边总时间: {right_time:.6f} 秒")
        print(f"  - 时间比例(左:右): {left_time / right_time:.2f}:1")

        print(f"\n效率分析:")
        expected_left_time = add_time * 99
        expected_right_time = mult_time * 2 + add_time
        print(f"  - 基于单次操作预测左边时间: {expected_left_time:.6f} 秒")
        print(f"  - 实际左边时间: {left_time:.6f} 秒")
        print(f"  - 预测准确度: {expected_left_time / left_time:.2f}")
        print(f"  - 基于单次操作预测右边时间: {expected_right_time:.6f} 秒")
        print(f"  - 实际右边时间: {right_time:.6f} 秒")
        print(f"  - 预测准确度: {expected_right_time / right_time:.2f}")

        return {
            'single_addition_time': add_time,
            'single_multiplication_time': mult_time,
            'left_side_time': left_time,
            'right_side_time': right_time,
            'left_operations': 99,
            'right_operations': 3,
            'left_throughput': 99 / left_time,
            'right_throughput': 1 / right_time,
            'time_ratio': left_time / right_time,
            'curve_order': self.order
        }


def main():
    print("初始化NIST P-256椭圆曲线运算基准测试系统...")
    benchmark = EllipticCurveAdditionBenchmarkP256()
    results = benchmark.run_comprehensive_benchmark()

    print("\n" + "=" * 80)
    print("最终结论 - NIST P-256椭圆曲线运算基准测试")
    print("=" * 80)
    print(f"性能总结:")
    print(f"  - 单次点加法时间: {results['single_addition_time']:.9f} 秒")
    print(f"  - 单次标量乘法时间: {results['single_multiplication_time']:.9f} 秒")
    print(f"  - 左边计算时间(100点累加): {results['left_side_time']:.6f} 秒")
    print(f"  - 右边计算时间(g^R + h^O): {results['right_side_time']:.6f} 秒")
    print(f"  - 时间比例(左:右): {results['time_ratio']:.2f}:1")
    print(f"  - 左边吞吐量: {results['left_throughput']:.2f} 次加法/秒")
    print(f"  - 右边吞吐量: {results['right_throughput']:.2f} 次/秒")
    print(f"  - 曲线阶: {results['curve_order']}")


if __name__ == "__main__":
    main()