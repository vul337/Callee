# CALLEE

Official code of CALLEE: Recovering Call Graphs for Binaries with Transfer and Contrastive Learning.

For ease of use, we have made some changes to the original implementation in the paper.

**Status: We are seeking solution for long-time data-sharing.**

## Usage

### Environment
Tested on Ubuntu 18.04 with 
 - Python3 (python-magic, gensim, numpy, torch, tqdm, capstone)
 - IDA Pro 7.6
 - CUDA 10.2

### Pipeline

***NOTE: This is a single-thread demo, consider multiprocessing for production or batch processing***

**a. Slice target binary with IDA**

```
python3 run-slice.py -i /path/to/binary -o /path/to/slices -n <num_workers> --ida_path /path/to/idat64
```

The script invokes IDA Pro to analyze the binary and perform slicing for indirect callsites and candidate callees.

**b. Tokenize the slices**

```
python3 preprocess.py -i /path/to/slices -o /path/to/tokenized_slices
```

The script tokenizes assembly instructions of slices.

**c. Generate embeddings with doc2vec**

```
python3 store_emb.py -i /path/to/tokenized_slices -o /path/to/embeddings --doc2vec_model /path/to/doc2vec_model
```

The script transforms slices into embeddings with pretrained doc2vec model.

**d. Predict with the Siamese network**

```
python3 pred.py -i /path/to/embeddings
```

The script outputs scores for each (indirect callsite, candidate callee).

## Tool for collecting indirect call 

Here is a qemu tcg plugin we've modified to collect indirect calls on x86_64: [`ibresolver`](https://github.com/Learner0x5a/ibresolver)



## Future Plan

 - [x] Code of core components
 - [ ] Pretrained doc2vec model
 - [x] Tool for collecting indirect call on x86_64 platform
 - [ ] Substitute the doc2vec model with transformers
 - [ ] ...