import os
import pickle
import torch
import gensim
import random
import numpy as np
from tqdm import tqdm
from glob import glob
from argparse import ArgumentParser

class CallPair(object):
    def __init__(self, line):
        caller_data_tokneized, callee_data_tokneized = line.split(' -> ')
        caller_sig, caller_insns = caller_data_tokneized.split('|')
        callee_sig, callee_insns = callee_data_tokneized.split('|')

        self.caller_sig = caller_sig 
        self.caller_insns = caller_insns 
        self.callee_sig = callee_sig 
        self.callee_insns = callee_insns 


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-i','--input_dir', type=str, help='input slice dir, which contains slice pairs to be embedded into vectors', 
                            nargs='?', default='slice-tokenized')
    parser.add_argument('--doc2vec_model', type=str, help='path to the trained doc2vec model',
                            nargs='?', default='./doc2vec.model.dbow')
    parser.add_argument('-o','--output_dir', type=str, nargs='?',
                        help='Output dir containing the embedded slice pairs', default='./aict-embeddings')
    args = parser.parse_args()
    
    os.makedirs(args.output_dir, exist_ok=True)

    call_pairs = {} 
    doc2vec_model = gensim.models.Doc2Vec.load(args.doc2vec_model)
    for slice_file in tqdm(glob('{}/*.slice.uniq'.format(args.input_dir))):
        call_pairs[slice_file] = []
        with open(slice_file, 'r') as f:
            for line in f:
                call_pairs[slice_file].append(CallPair(line))
    
    call_pairs_pkl = {}

    for slice_file in call_pairs:
        call_pairs_pkl[slice_file] = []
        for idx, pair in tqdm(enumerate(call_pairs[slice_file])):
            caller_emb = doc2vec_model.infer_vector(pair.caller_insns.strip().split())
            callee_emb = doc2vec_model.infer_vector(pair.callee_insns.strip().split())

            call_pairs_pkl[slice_file].append([pair.caller_sig, caller_emb, pair.callee_sig, callee_emb])
        with open('{}.pkl'.format(os.path.join(args.output_dir, slice_file.split(os.path.sep)[-1])), 'wb') as f:
            pickle.dump(call_pairs_pkl[slice_file], f)

