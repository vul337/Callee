import os
import magic
from concurrent.futures import ProcessPoolExecutor
import subprocess
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-i','--bin', type=str, help='binary')
parser.add_argument('-o','--output_dir', type=str, nargs='?',
                    help='Output dir', default='./output-slice')
parser.add_argument('-n','--workers', type=int, nargs='?',
                    help='Max Workers', default=1)
parser.add_argument('--ida_path', type=str, nargs='?',
                    help='idapro dir', default='/workspace/idapro-7.6/idat64')

args = parser.parse_args()


def run(bin_path, output_dir):
    filename = bin_path.split(os.path.sep)[-1]
    script_cmd = './util_slice.py {}'.format(output_dir)
    ida_cmd = 'env TERM=xterm {} -L"log/{}.log" -A -S"{}" {}'.format(args.ida_path, filename, script_cmd, bin_path)
    print(ida_cmd)
    subprocess.run(ida_cmd, shell=True)

def main():
    output_dir = os.path.join(args.output_dir,'aict')
    os.makedirs(output_dir, exist_ok=True)
    
    run(args.bin, output_dir)

if __name__ == '__main__':
    main()
