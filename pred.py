import pickle
import torch
import random
import numpy as np
from tqdm import tqdm
from torch.utils.data import DataLoader
from SiameseModel import ContrastiveClassifier
import numpy as np
from glob import glob
from argparse import ArgumentParser


class AICTPairWithPreGenEmbDataset(torch.utils.data.Dataset):
    def __init__(self, dataset_path):
        self.dataset_path = dataset_path
        print('Loading dataset...')
        self.emb_files = []
        self.load_data()

    def __getitem__(self, idx): # per callsite
        caller_embs = []
        callee_embs = []
        with open(self.emb_files[idx], 'rb') as f:
            call_pairs = pickle.load(f)
            for caller_sig, caller_emb, callee_sig, callee_emb in tqdm(call_pairs):
                caller_embs.append(caller_emb)
                callee_embs.append(callee_emb)
        print(self.emb_files[idx])
        return self.emb_files[idx], np.array(caller_embs), np.array(callee_embs)

    def __len__(self):
        return len(self.emb_files)

    def load_data(self):
        for slice_file in tqdm(glob('{}/*.pkl'.format(self.dataset_path))):
            self.emb_files.append(slice_file)


if torch.cuda.is_available():
    dev=torch.device('cuda')
else:
    dev=torch.device('cpu')
print(dev)



if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-i','--emb_dir', type=str, help='embeddings dir', nargs='?', default='./aict-embeddings')
    parser.add_argument('--model', type=str, help='siamese network model', nargs='?', default='./model_bce_with_pregen_emb_2.pth')

    args = parser.parse_args()


    model = ContrastiveClassifier(3, 100, 256, 128, 1, 256, 1).to(dev)
    params_load = torch.load(args.model)['state_dict']
    model.load_state_dict(params_load)

    aict_loader = DataLoader(AICTPairWithPreGenEmbDataset(args.emb_dir), batch_size = 1, num_workers=0, shuffle=True)
    model.eval()
    icts = {}
    with torch.no_grad():
        for i, (binary_name, caller_embs, callee_embs) in tqdm(enumerate(aict_loader)):
            binary_name = binary_name[0]

            caller_embs = caller_embs.to(dev)
            caller_embs = torch.squeeze(caller_embs)
            callee_embs = callee_embs.to(dev)
            callee_embs = torch.squeeze(callee_embs)

            preds = model(caller_embs, callee_embs)

            print(f'Callsite {i}, preds:', preds.cpu().numpy())
