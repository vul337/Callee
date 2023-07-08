import os
from tqdm import tqdm
from util_tokenizer import asmTokenizer
from argparse import ArgumentParser

def get_slice_iter(_dir):
    for root,parent,files in os.walk(_dir):
        for slice_file in files:
            filepath = os.path.join(root, slice_file)
            filesize = os.path.getsize(filepath)/(1024*1024)
            if filesize > 50:
                print('Found large file: {}\t{} MB'.format(slice_file, filesize))
                continue

            slice_paris_tokenized = []
            with open(filepath,'r') as f:
                slice_pairs = f.readlines()
            for line in slice_pairs:
                caller_data, callee_data = line.split(' -> ')
                caller_sig, caller = caller_data.split('|')
                callee_sig, callee = callee_data.split('|')
                caller_insns = caller.strip().split('\t')
                callee_insns = callee.strip().split('\t')
                tokenized_caller = tokenizer.tokenize_doc(caller_insns)
                tokenized_callee = tokenizer.tokenize_doc(callee_insns)

                caller_data_tokenized = '{}|{}'.format(caller_sig, tokenized_caller)
                callee_data_tokenized = '{}|{}'.format(callee_sig, tokenized_callee)
                slice_paris_tokenized.append((caller_data_tokenized, callee_data_tokenized))

            yield slice_file, slice_paris_tokenized 
                    

if __name__ == '__main__':

    parser = ArgumentParser()
    parser.add_argument('-i','--slice_dir', type=str, help='slice dir', nargs='?', default='slice')
    parser.add_argument('-o','--output_dir', type=str, nargs='?',
                        help='Output tokenized slice dir', default='./slice-tokenized')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    tokenizer = asmTokenizer()
    for slice_file, slice_paris_tokenized in tqdm(get_slice_iter(args.slice_dir)):
        with open(os.path.join(args.output_dir, slice_file),'w') as f:
            for caller_data_tokenized, callee_data_tokenized in slice_paris_tokenized:
                f.write('{} -> {}\n'.format(caller_data_tokenized, callee_data_tokenized))

        os.system("awk '!seen[$0]++' {} > {}.uniq".format(os.path.join(args.output_dir, slice_file), os.path.join(args.output_dir, slice_file)))
