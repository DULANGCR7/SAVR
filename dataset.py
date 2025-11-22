import os
import torch
import numpy as np
from torchvision import datasets, transforms
from torch.utils.data import DataLoader, TensorDataset
import random

class GetDataSet(object):
    def __init__(self, is_iid=True):
        self.is_iid = is_iid

    def load_data(self, seed=None):
        """加载数据，支持随机种子"""
        if seed is not None:
            torch.manual_seed(seed)
            np.random.seed(seed)
            random.seed(seed)

        transform = transforms.Compose([
            transforms.ToTensor(),
            transforms.Normalize((0.1307,), (0.3081,))
        ])

        train_dataset = datasets.MNIST(root='./MNIST', train=True, download=True, transform=transform)
        test_dataset = datasets.MNIST(root='./MNIST', train=False, download=True, transform=transform)

        if self.is_iid:
            # IID 分布：将训练集随机分配给每个客户端
            client_num = 20
            data_size = len(train_dataset) // client_num
            
            # 随机打乱数据索引
            indices = list(range(len(train_dataset)))
            random.shuffle(indices)
            
            train_loader = []
            for i in range(client_num):
                start_idx = i * data_size
                end_idx = (i + 1) * data_size if i < client_num - 1 else len(train_dataset)
                client_indices = indices[start_idx:end_idx]
                client_dataset = torch.utils.data.Subset(train_dataset, client_indices)
                client_loader = DataLoader(client_dataset, batch_size=64, shuffle=True)
                train_loader.append(client_loader)
        else:
            # 非 IID 分布（按标签划分）- 修复版本
            targets = train_dataset.targets.numpy()
            clients_data = [[] for _ in range(20)]  # 20个客户端
            
            # 方法1: 每个客户端分配2-3个标签的数据
            labels_per_client = 2  # 每个客户端有2个标签的数据
            
            for client_idx in range(20):
                # 为每个客户端随机选择2个标签
                client_labels = np.random.choice(10, labels_per_client, replace=False)
                
                for label in client_labels:
                    # 获取该标签的所有数据索引
                    label_indices = np.where(targets == label)[0]
                    # 随机选择一部分数据分配给该客户端
                    num_samples = len(label_indices) // 3  # 每个标签的数据分给大约3个客户端
                    selected_indices = np.random.choice(label_indices, num_samples, replace=False)
                    clients_data[client_idx].extend(selected_indices.tolist())
            
            # 方法2: 确保每个客户端都有数据（备用方案）
            # 检查是否有客户端数据为空，如果有则重新分配
            for client_idx in range(20):
                if len(clients_data[client_idx]) == 0:
                    # 为空客户端随机分配一些数据
                    all_indices = list(range(len(train_dataset)))
                    random.shuffle(all_indices)
                    clients_data[client_idx].extend(all_indices[:100])  # 分配100个样本
            
            # 创建客户端 DataLoader
            train_loader = []
            for i, client_data in enumerate(clients_data):
                if len(client_data) == 0:
                    # 如果还有空客户端，使用备用数据
                    all_indices = list(range(len(train_dataset)))
                    random.shuffle(all_indices)
                    client_data = all_indices[:100]
                    print(f"警告: 客户端 {i} 数据为空，已分配备用数据")
                
                client_dataset = torch.utils.data.Subset(train_dataset, client_data)
                client_loader = DataLoader(client_dataset, batch_size=64, shuffle=True)
                train_loader.append(client_loader)
                
                # 打印每个客户端的数据信息（可选）
                client_targets = [targets[idx] for idx in client_data]
                unique_labels = np.unique(client_targets)
                print(f"客户端 {i}: {len(client_data)} 个样本, 标签: {unique_labels}")

        test_loader = DataLoader(test_dataset, batch_size=64, shuffle=False)
        return train_loader, test_loader