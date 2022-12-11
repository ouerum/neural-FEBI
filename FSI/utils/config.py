import torch
import os

os.environ["CUDA_VISIBLE_DEVICES"] = "0"
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# device = torch.device("cpu")

trainning_epoches = 150
min_block_freq = 5
print_step = 100
lr = 0.01
lr_decay = 0.1
batch_size = 10
grad_clip = 5.
workers = 5


instr_emb_dim = 30
instr_rnn_dim = 300
instr_rnn_layers = 1
block_emb_dim = 300
block_rnn_dim = 200
block_rnn_layers = 1

dropout = 0.1

training_ratio = 0.4
val_ratio = 0.1
test_ratio = 0.5


contracts_dir = ""
data_dir = ""
temp_dir = ""

dtype = "FSI-biLSTM-CRF"

modle_output = ""

fsi_result_path = ""

address_path = ""