import os
import torch
from torch import optim
import numpy as np
from loguru import logger
from model import CNN, MLP
from client import Client
from dataset import GetDataSet
import matplotlib.pyplot as plt
import pandas as pd
from scipy import stats

# 设置日志文件路径
log_file_path = "training.log"

# 配置日志记录，添加文件处理器
logger.add(log_file_path, format="{time} {level} {message}", level="INFO", rotation="10 MB")

class Server:
    def __init__(self, model_type='MLP', is_iid=True, num_runs=3):
        self.client_nums = 20
        self.global_model = []
        self.lr = 0.01
        self.client_sids = []
        self.clients = {}
        self.accuracies_with_malicious = []  
        self.accuracies_without_malicious = []  
        self.accuracies_fedavg = []  
        self.N = 1000000007
        self.g = 2
        self.model_type = model_type
        self.is_iid = is_iid
        self.num_runs = num_runs  
        self.all_results = []  

    def init_global_model(self):
        logger.info(f'初始化全局模型! 模型类型: {self.model_type}')
        os.environ['CUDA_VISIBLE_DEVICES'] = '0'
        self.dev = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")

        if self.model_type == 'CNN':
            net = CNN()
        else:  # MLP
            net = MLP()
                
        self.loss_func = torch.nn.CrossEntropyLoss()
        self.opti = optim.SGD(net.parameters(), lr=self.lr)
        self.net = net.to(self.dev)
        par = net.state_dict().copy()
        self.global_model = [par[key].cpu().numpy() for key in par.keys()]

    def init_dataset(self, seed=None):
        logger.info(f'初始化MNIST数据集! 数据分布: {"IID" if self.is_iid else "非IID"}')
        dataset = GetDataSet(is_iid=self.is_iid)
        self.train_loaders, self.test_loader = dataset.load_data(seed=seed)

    def init_clients(self):
        logger.info('初始化客户端!')
        self.client_sids = []
        self.clients = {}
        for i in range(self.client_nums):
            client_id = f'client_{i}'
            self.client_sids.append(client_id)
            is_malicious = True if i < 6 else False  
            self.clients.update({
                client_id: Client(
                    client_id, 
                    self.train_loaders[i], 
                    is_malicious,
                    model_type=self.model_type
                )
            })

    def evaluate_global_model(self, params):
        if self.model_type == 'CNN':
            net = CNN()
        else:  
            net = MLP()
                
        par = net.state_dict().copy()
        for key, param in zip(par.keys(), params):
            par[key] = torch.from_numpy(param)
        net.load_state_dict(par, strict=True)
        net = net.to(self.dev)
        net.eval()
        correct = 0
        total = 0
        with torch.no_grad():
            for data, label in self.test_loader:
                data, label = data.to(self.dev), label.to(self.dev)
                outputs = net(data)
                _, predicted = torch.max(outputs.data, 1)
                total += label.size(0)
                correct += (predicted == label).sum().item()
        accuracy = 100 * correct / total
        return accuracy

    def _decrypt_aggregate(self, encrypted_params_list, r_values_list, aggregation_type="correct"):
        aggregated_params = []
        
        if aggregation_type == "correct":
            for param_idx in range(len(encrypted_params_list[0])):
                param_sum = np.zeros_like(encrypted_params_list[0][param_idx])
                for client_idx in range(len(encrypted_params_list)):
                    param_sum += encrypted_params_list[client_idx][param_idx]
                avg_param = param_sum / len(encrypted_params_list)
                aggregated_params.append(avg_param)
                
        else:  
            aggregated_params = self._real_decrypt_aggregate(encrypted_params_list, r_values_list)
            
        return aggregated_params

    def _real_decrypt_aggregate(self, encrypted_params_list, r_values_list):
        aggregated_params = []
        N_sq = self.N * self.N
        
        for param_idx in range(len(encrypted_params_list[0])):
            aggregated_encrypted = np.ones_like(encrypted_params_list[0][param_idx], dtype=np.int64)
            for client_idx in range(len(encrypted_params_list)):
                aggregated_encrypted = (aggregated_encrypted * encrypted_params_list[client_idx][param_idx]) % N_sq
            
            R_product = 1
            for client_idx in range(len(r_values_list)):
                r_u = r_values_list[client_idx][param_idx]
                R_product = (R_product * r_u) % self.N
            
            R_N = pow(R_product, self.N, N_sq)
            
            R_N_inv = pow(R_N, -1, N_sq)
            g_sum_x = (aggregated_encrypted * R_N_inv) % N_sq
            
            decrypted_sum = self._approximate_decrypt(g_sum_x)

            avg_param = decrypted_sum / len(encrypted_params_list)
            aggregated_params.append(avg_param)
            
        return aggregated_params

    def _approximate_decrypt(self, g_sum_x):
        result = np.zeros_like(g_sum_x, dtype=np.float64)
        for idx in np.ndindex(g_sum_x.shape):
            val = int(g_sum_x[idx])
            if val > self.g:
                try:
                    log_val = np.log(val) / np.log(self.g)
                    result[idx] = log_val / 10000.0  
                except:
                    result[idx] = 0.0
            else:
                result[idx] = 0.0
        return result

    def _print_round_summary(self, round_idx, accuracies):
        print("\n" + "="*50)
        print(f" 第 {round_idx + 1:2d} 轮训练完成 - 全局模型准确度总结")
        print("="*50)

        methods = [
            ("FedAvg", accuracies['fedavg']),
            ("正确聚合", accuracies['correct']),
            ("错误聚合", accuracies['incorrect'])
        ]
        
        for method_name, accuracy in methods:
            print(f"│ {method_name:8} │ {accuracy:6.2f}% │")
        
        print("="*50)
        

    def single_run(self, run_id):
        logger.info(f'开始第 {run_id + 1} 次运行')
        
        self.init_dataset(seed=run_id)
        self.init_clients()
        
        self.init_global_model()
        
        run_results = {
            'fedavg': [],
            'correct': [],
            'incorrect': []
        }
        
        print(f"\n{'#'*80}")
        print(f"🚀 开始第 {run_id + 1} 次联邦学习运行")
        print(f"📊 模型: {self.model_type} | 数据分布: {'IID' if self.is_iid else '非IID'}")
        print(f"👥 客户端: {self.client_nums}个 (6个恶意客户端)")
        print(f"🔄 总轮次: 20")
        print(f"{'#'*80}")
        
        for round_idx in range(20):  
            logger.info(f'第 {run_id + 1} 次运行, 第 {round_idx + 1} 轮训练')
            
            fedavg_params = []
            for client_id, client in self.clients.items():
                client.is_malicious = False  
                raw_params, _ = client.local_train(
                    self.global_model, self.lr, 1, self.client_nums, 
                    use_encryption=False, aggregation_type="fedavg"
                )
                fedavg_params.append(raw_params)

            aggregated_fedavg = []
            for param_idx in range(len(fedavg_params[0])):
                param_sum = np.zeros_like(fedavg_params[0][param_idx])
                for c_params in fedavg_params:
                    param_sum += c_params[param_idx]
                aggregated_fedavg.append(param_sum / len(fedavg_params))
            
            accuracy_fedavg = self.evaluate_global_model(aggregated_fedavg)
            run_results['fedavg'].append(accuracy_fedavg)

            correct_encrypted_params = []
            correct_r_values = []
            for client_id, client in self.clients.items():
                client.is_malicious = False  
                encrypted_params, r_values = client.local_train(
                    self.global_model, self.lr, 1, self.client_nums,
                    use_encryption=True, aggregation_type="correct"
                )
                correct_encrypted_params.append(encrypted_params)
                correct_r_values.append(r_values)

            aggregated_correct = self._decrypt_aggregate(
                correct_encrypted_params, correct_r_values, "correct"
            )
            accuracy_correct = self.evaluate_global_model(aggregated_correct)
            run_results['correct'].append(accuracy_correct)

            incorrect_encrypted_params = []
            incorrect_r_values = []
            for client_id, client in self.clients.items():
                client.is_malicious = True if int(client_id.split('_')[1]) < 6 else False
                encrypted_params, r_values = client.local_train(
                    self.global_model, self.lr, 1, self.client_nums,
                    use_encryption=True, aggregation_type="incorrect"
                )
                incorrect_encrypted_params.append(encrypted_params)
                incorrect_r_values.append(r_values)

            aggregated_incorrect = self._decrypt_aggregate(
                incorrect_encrypted_params, incorrect_r_values, "incorrect"
            )
            accuracy_incorrect = self.evaluate_global_model(aggregated_incorrect)
            run_results['incorrect'].append(accuracy_incorrect)

            current_accuracies = {
                'fedavg': accuracy_fedavg,
                'correct': accuracy_correct,
                'incorrect': accuracy_incorrect
            }
            self._print_round_summary(round_idx, current_accuracies)

            self.global_model = aggregated_fedavg

        return run_results

    def calculate_confidence_intervals(self, data, confidence=0.95):
        if len(data) <= 1:
            return np.mean(data), np.mean(data), np.mean(data)
        mean = np.mean(data)
        std_err = stats.sem(data)  
        h = std_err * stats.t.ppf((1 + confidence) / 2, len(data) - 1)  
        return mean, mean - h, mean + h

    def start(self):
        logger.info(f'开始联邦学习训练! 模型类型: {self.model_type}, 数据分布: {"IID" if self.is_iid else "非IID"}, 运行次数: {self.num_runs}')
        
        self.init_global_model()

        all_runs_results = []
        for run_id in range(self.num_runs):
            run_results = self.single_run(run_id)
            all_runs_results.append(run_results)
            logger.info(f'完成第 {run_id + 1}/{self.num_runs} 次运行')

        self.process_multiple_runs(all_runs_results)

        self._plot_results()

        self._generate_results_table()

    def process_multiple_runs(self, all_runs_results):
        num_rounds = 20
        
        self.means = {
            'fedavg': np.zeros(num_rounds),
            'correct': np.zeros(num_rounds),
            'incorrect': np.zeros(num_rounds)
        }
        self.confidence_intervals = {
            'fedavg': np.zeros((num_rounds, 2)),
            'correct': np.zeros((num_rounds, 2)),
            'incorrect': np.zeros((num_rounds, 2))
        }
        
        for round_idx in range(num_rounds):
            for method in ['fedavg', 'correct', 'incorrect']:
                round_accuracies = [run[method][round_idx] for run in all_runs_results]
                mean, ci_low, ci_high = self.calculate_confidence_intervals(round_accuracies)
                self.means[method][round_idx] = mean
                self.confidence_intervals[method][round_idx] = [ci_low, ci_high]

    def _plot_results(self):
        plt.figure(figsize=(12, 8))
        rounds = range(20)
        
        methods = [
            ('fedavg', 'red', '-', 'FedAvg'),
            ('correct', 'green', '--', '正确聚合'),
            ('incorrect', 'black', '-.', '错误聚合')
        ]
        
        for method, color, linestyle, label in methods:
            mean = self.means[method]
            ci = self.confidence_intervals[method]
            
            plt.plot(rounds, mean, color=color, linestyle=linestyle, 
                    linewidth=3, label=label)
            
            plt.fill_between(rounds, ci[:, 0], ci[:, 1], 
                           color=color, alpha=0.2)
        
        plt.xlabel('训练轮次', fontsize=16)
        plt.ylabel('测试准确率 (%)', fontsize=16)
        plt.title(f'联邦学习聚合方法比较 - {self.model_type}模型 ({"IID" if self.is_iid else "非IID"}数据)', fontsize=18)
        plt.legend(fontsize=14)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(f'result_{self.model_type}_{"iid" if self.is_iid else "noniid"}.png', dpi=300, bbox_inches='tight')
        plt.show()

    def _generate_results_table(self):
        logger.info("=== 详细结果分析（置信区间 95%） ===")
        
        key_rounds = [0, 4, 9, 14, 19] 
        table_data = []
        for round_idx in key_rounds:
            row = {'Round': round_idx + 1}
            for method in ['fedavg', 'correct', 'incorrect']:
                mean = self.means[method][round_idx]
                ci_low, ci_high = self.confidence_intervals[method][round_idx]
                row[f'{method.upper()}_Mean'] = f"{mean:.2f}%"
                row[f'{method.upper()}_CI'] = f"({ci_low:.2f}%, {ci_high:.2f}%)"
            table_data.append(row)

        df = pd.DataFrame(table_data)
        print("\n" + "="*80)
        print(f"联邦学习结果汇总表 (模型: {self.model_type}, 数据: {'IID' if self.is_iid else '非IID'}, 运行次数: {self.num_runs})")
        print("="*80)
        print(df.to_string(index=False))
        
        df.to_csv(f'results_table_{self.model_type}_{"iid" if self.is_iid else "noniid"}_{self.num_runs}runs.csv', index=False)
        
        logger.info("=== 最终轮次结果（20轮）===")
        for method_name, method_key in [('FedAvg', 'fedavg'), ('正确聚合', 'correct'), ('错误聚合', 'incorrect')]:
            mean = self.means[method_key][-1]
            ci_low, ci_high = self.confidence_intervals[method_key][-1]
            logger.info(f"{method_name}: {mean:.2f}% (95% CI: {ci_low:.2f}% - {ci_high:.2f}%)")

def main():
    print("选择模型类型:")
    print("1. MLP")
    print("2. CNN")
    model_choice = input("请输入选择 (1 或 2): ").strip()
    
    print("选择数据分布:")
    print("1. IID 分布")
    print("2. 非IID 分布")
    data_choice = input("请输入选择 (1 或 2): ").strip()
    
    print("选择运行次数 (用于计算置信区间):")
    print("建议: 3-5次 (更多次数更准确但耗时更长)")
    num_runs_input = input("请输入运行次数: ").strip()
    num_runs = int(num_runs_input) if num_runs_input else 3
    
    model_type = 'MLP' if model_choice == '1' else 'CNN'
    is_iid = True if data_choice == '1' else False
    
    print(f"\n开始训练MNIST数据集 - 模型: {model_type}, 数据分布: {'IID' if is_iid else '非IID'}, 运行次数: {num_runs}")
    print("=" * 60)
    
    server = Server(model_type=model_type, is_iid=is_iid, num_runs=num_runs)
    server.start()

if __name__ == '__main__':
    main()