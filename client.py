import torch
from torch import nn, optim
import numpy as np
import torch.nn.functional as F
from loguru import logger
from model import CNN, MLP

class Client(object):
    def __init__(self, cid, train_dl, is_malicious=False, model_type='MLP'):
        self.net = None
        self.opti = None
        self.loss_func = None
        self.dev = None
        self.id = cid
        self.train_dl = train_dl
        self.is_malicious = is_malicious
        self.model_type = model_type
        self.N = 1000000007
        self.g = 2

    def local_train(self, params, lr, epoch, num_clients, use_encryption=True, aggregation_type="correct"):
        """
        本地训练方法
        :param params
        :param lr 
        :param epoch
        :param num_clients 
        :param use_encryption
        :param aggregation_type
        """
        # 设备配置
        self.dev = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
        
        # 根据配置选择模型
        if self.model_type == 'CNN':
            net = CNN()
        else:  # MLP
            net = MLP()
                
        self.loss_func = F.cross_entropy
        self.opti = optim.SGD(net.parameters(), lr=lr)
        self.net = net.to(self.dev)

        state_dict = net.state_dict()
        for i, key in enumerate(state_dict.keys()):
            state_dict[key] = torch.from_numpy(params[i])
        net.load_state_dict(state_dict)
        self.net = net.to(self.dev)

        self.net.train()
        for epoch_idx in range(epoch):
            train_loss = 0
            batches = 0
            sum_accu = 0
            num = 0
            for data, label in self.train_dl:
                data, label = data.to(self.dev), label.to(self.dev)
                self.opti.zero_grad()
                preds = self.net(data)
                loss = self.loss_func(preds, label)
                loss.backward()
                self.opti.step()
                train_loss += loss.item()
                batches += 1
                _, predicted = torch.max(preds.data, 1)
                sum_accu += (predicted == label).float().mean()
                num += 1

            # 记录训练日志（减少日志输出频率）
            if epoch_idx == epoch - 1:  # 只记录最后一轮
                logger.debug('\t客户端: {} | 轮次: {} | 损失: {:.3f} | 准确率: {:.3f}'.format(
                    self.id, epoch_idx, train_loss / batches, sum_accu / num))

        # 返回更新后的参数
        par = self.net.state_dict()
        
        if aggregation_type == "fedavg":
            return [par[key].cpu().numpy() for key in par.keys()], None
            
        elif use_encryption:

            encrypted_params = []
            r_values = []  
            
            for key in par.keys():
                param = par[key].cpu().numpy()  
                
                if aggregation_type == "correct":
                    r_u = np.random.randint(1, 1000)  
                    encrypted_param = param.copy()
                    
                elif aggregation_type == "incorrect":
                    if self.is_malicious:
                        r_u = np.random.randint(10000, 100000)  
                        logger.debug(f"恶意客户端 {self.id} 生成错误 r_u: {r_u}")
                    else:
                        r_u = np.random.randint(1, 1000)
                    
                    encrypted_param = self._real_encrypt(param, r_u)
                
                encrypted_params.append(encrypted_param)
                r_values.append(r_u)
                
            logger.debug(f"客户端 {self.id} 完成加密，r_u: {r_values[:3]}...")
            return encrypted_params, r_values
            
        else:
            return [par[key].cpu().numpy() for key in par.keys()], None

    def _real_encrypt(self, x, r):
        N_sq = self.N * self.N
        
        x_scaled = (x * 10000).astype(np.int64)  
        
        encrypted = np.zeros_like(x_scaled, dtype=np.int64)
        for idx in np.ndindex(x_scaled.shape):
            x_val = int(x_scaled[idx])
            r_val = int(r)
            

            if x_val < 0:
                x_val = abs(x_val)  
            elif x_val == 0:
                x_val = 1  
            
            g_x = pow(self.g, x_val, N_sq)
            
            r_N = pow(r_val, self.N, N_sq)
            
            encrypted[idx] = (g_x * r_N) % N_sq
            
        return encrypted

    def get_client_id(self):
        return self.id

    def get_malicious_status(self):
        return self.is_malicious

    def set_malicious(self, is_malicious):
        self.is_malicious = is_malicious
        logger.debug(f"客户端 {self.id} 恶意状态设置为: {is_malicious}")