import os
import pickle
from tqdm import tqdm
from typing import Dict, List, Tuple
import idc
import idaapi
import idautils
import ida_pro
import ida_auto
import ida_nalt
import ida_funcs
ida_auto.auto_wait()

from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

text_start = idc.get_segm_by_sel(idc.selector_by_name(".text"))
text_end = idc.get_segm_end(text_start)
got_start = idc.get_segm_by_sel(idc.selector_by_name(".got"))
got_end = idc.get_segm_end(got_start)
got_plt_start = idc.get_segm_by_sel(idc.selector_by_name(".got.plt"))
got_plt_end = idc.get_segm_end(got_plt_start)
plt_start = idc.get_segm_by_sel(idc.selector_by_name(".plt"))
plt_end = idc.get_segm_end(plt_start)
plt_got_start = idc.get_segm_by_sel(idc.selector_by_name(".plt.got"))
plt_got_end = idc.get_segm_end(plt_got_start)

at_blacklist = ['main', '_start', '__do_global_dtors_aux','frame_dummy', '__lib_csu_init', '__lib_csu_fini']
exit_list = ["exit","_exit","terminate","_terminate"]
init_reg_map = {"rdi":"rdi", "rsi":"rsi", "rdx":"rdx", "rcx":"rcx",  "r8":"r8",  "r9":"r9",  "rax":"rax", "rsp":"rsp", "rbp":"rbp",
            "edi":"rdi", "esi":"rsi", "edx":"rdx", "ecx":"rcx", "r8d":"r8", "r9d":"r9", "eax":"rax", "esp":"rsp", "ebp":"rbp",
             "di":"rdi",  "si":"rsi",  "dx":"rdx",  "cx":"rcx", "r8w":"r8", "r9w":"r9",  "ax":"rax",  "sp":"rsp",  "bp":"rbp",
            "dil":"rdi", "sil":"rsi",  "dl":"rdx",  "cl":"rcx", "r8b":"r8", "r9b":"r9",  "al":"rax", "spl":"rsp", "bpl":"rbp" ,
            "xmm0":"zmm0","ymm0":"zmm0","zmm0":"zmm0",
            "xmm1":"zmm1","ymm1":"zmm1","zmm1":"zmm1",
            "xmm2":"zmm2","ymm2":"zmm2","zmm2":"zmm2",
            "xmm3":"zmm3","ymm3":"zmm3","zmm3":"zmm3",
            }
reversed_reg_map = {
    "rdi": ["rdi","edi","di","dil"],
    "rsi": ["rsi","esi","si","sil"],
    "rdx": ["rdx","edx","dx","dl"],
    "rcx": ["rcx","ecx","cx","cl"],
    "r8": ["r8","r8d","r8w","r8b"],
    "r9": ["r9","r9d","r9w","r9b"],
    "rax": ["rax","eax","ax","al"],
    "rsp": ["rsp","esp","sp","spl"],
    "rbp": ["rbp","ebp","bp","bpl"],
    "zmm0": ["zmm0","ymm0","xmm0"],
    "zmm1": ["zmm1","ymm1","xmm1"],
    "zmm2": ["zmm2","ymm2","xmm2"],
    "zmm3": ["zmm3","ymm3","xmm3"],
}

reg_rw_threshold = 1
call_ins_threshold = 1
j_ins_threshold = 1

SKIP_THRESHOLD = 5
ALL_FUNCTIONS = list(idautils.Functions())

def getRealAddr(addr):

    initAddr = addr

    while initAddr < text_start or initAddr >= text_end:
        initAddr = idc.get_operand_value(initAddr, 0)

        xref = idautils.XrefsFrom(initAddr,0)
        xreflist = list(xref)
        lenlist = len(xreflist)
        if lenlist == 1:
            initAddr = xreflist[0].to
        elif lenlist == 0:
            initAddr = 0
            break
        else:
            print("0x%x: more than 1 xref?"%initAddr)

    return initAddr

def is_tail_call(opcode, addr):
    flag = False
    if opcode.startswith('j'):
        if idc.get_operand_value(addr, 0) in ALL_FUNCTIONS: 
            flag = True
        elif opcode == 'jmp'  and (not ' short ' in idc.GetDisasm(addr)): 
            flag = True

    return flag

def getDisasmCapstone(addr):
    insn = None
    r,w = [],[]
    code = idc.get_bytes(addr, idc.get_item_size(addr))
    if not code:
        return '',[],[]
    for i in md.disasm(code, addr):
        insn = "%s %s" % (i.mnemonic, i.op_str)
        if insn.startswith('nop'):
            continue
        (regs_read, regs_write) = i.regs_access()
        if regs_read:
            for reg in regs_read:
                # print "\tRead REG: %s" %(i.reg_name(reg))
                r.append("%s"%i.reg_name(reg))
        if regs_write:
            for reg in regs_write:
                # print "\tWrite REG: %s" %(i.reg_name(reg))
                w.append("%s"%i.reg_name(reg))

    return insn,r,w


def get_num_insns(func_ea):

    if func_ea == idc.BADADDR:
        iter = func_ea
        backward_count = 0
        while backward_count < 100:
            backward_count += 1
            iter = idc.prev_head(iter)
            if iter in ALL_FUNCTIONS or idc.print_insn_mnem(iter) == 'retn':
                break
        func_start = idc.next_head(iter)

        iter = func_ea
        forward_count = 0
        while forward_count < 100:
            forward_count += 1
            iter = idc.next_head(iter)
            if iter in ALL_FUNCTIONS or idc.print_insn_mnem(iter) == 'retn':
                break
        func_end = idc.prev_head(iter)

        num_insns = backward_count + forward_count

    else:
        num_insns = len(list(idautils.FuncItems(func_ea)))

    return num_insns

def get_func_boudary(ea):
    func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)

    if func_ea == idc.BADADDR:
        iter = func_ea
        backward_count = 0
        while backward_count < 100:
            backward_count += 1
            iter = idc.prev_head(iter)
            if iter in ALL_FUNCTIONS or idc.print_insn_mnem(iter) == 'retn':
                break
        functionStart = idc.next_head(iter)

        iter = func_ea
        forward_count = 0
        while forward_count < 100:
            forward_count += 1
            iter = idc.next_head(iter)
            if iter in ALL_FUNCTIONS or idc.print_insn_mnem(iter) == 'retn':
                break
        functionEnd = idc.prev_head(iter)

    else:
        functionStart = idc.get_func_attr(ea, idc.FUNCATTR_START)
        functionEnd = idc.find_func_end(functionStart)

    return functionStart, functionEnd



class Callee:
    def __init__(self, addr) -> None:
        self.addr = addr
        self.slices = []
        self.signature = []
        self.functionStart = self.addr
        self.functionEnd = idc.find_func_end(self.functionStart)
        self.functionName = idc.get_func_name(self.addr)
        self.num_insns = len(list(idautils.FuncItems(self.functionStart)))

    def _SliceOnRegs(self, reg_count : dict, reg_map : dict) -> Tuple[list, list]:

        addr = self.addr
        signature = []
        slices = []
        ret_flag = False

        call_ins_count = 0 
        j_ins_count = 0 

        reg_status = {} 
        for key in reg_count:
            reg_status[key] = ""

        while self.functionStart <= addr < self.functionEnd:
            flag = False 

            opcode = idc.print_insn_mnem(addr)
            if opcode.startswith("nop"):
                addr = idc.next_head(addr)
                continue

            if opcode.startswith("call"):
                if call_ins_count < call_ins_threshold: 
                    call_ins_count += 1
                    flag = True

            if j_ins_count < j_ins_threshold:
                if is_tail_call(opcode, addr):
                    j_ins_count += 1
                    flag = True

            insn,r,w = getDisasmCapstone(addr)
            for reg in r:
                if not reg in reg_map.keys(): 
                    continue
                reg_status[reg_map[reg]] += "r"
                if reg_map[reg] == "rax": 
                    continue
                if reg_count[reg_map[reg]] > reg_rw_threshold: 
                    continue
                reg_count[reg_map[reg]] += 1 

                flag = True

            for reg in w:
                if not reg in reg_map.keys(): 
                    continue
                reg_status[reg_map[reg]] += "w"
                if reg_map[reg] != "rax": 
                    continue
                if reg_count[reg_map[reg]] > reg_rw_threshold: 
                    continue
                reg_count[reg_map[reg]] += 1
                ret_flag = True
                flag = True

            if flag:
                # print(insn)
                slices.append(insn) 

            addr = idc.next_head(addr)


        float_reg_count = {}
        for key in reg_count:
            if key.startswith("zmm"):
                float_reg_count[key] = reg_count[key]

        for reg in reg_count:
            if reg_count[reg] > 0:
                signature.append(reg)

        for reg in float_reg_count:
            if float_reg_count[reg] > 0 and (reg not in signature):
                signature.append(reg)

        if ret_flag and ("rax" not in signature):
            signature.append("rax")

        return (signature, slices)

    def calleeSlice(self):

        reg_count = {"rdi":0,"rsi":0,"rdx":0,"rcx":0,"r8":0,"r9":0,"rsp":0,"rbp":0,"rax":0,"zmm0":0,"zmm1":0,"zmm2":0,"zmm3":0}
        signature,raw_slices = self._SliceOnRegs(reg_count, init_reg_map) 

        new_reg_count = {}
        new_reg_map = {}
        for reg in signature:
            new_reg_count[reg] = 0
            for key in reversed_reg_map[reg]:
                new_reg_map[key] = reg

        signature,refined_slices = self._SliceOnRegs(new_reg_count, new_reg_map)

        self.signature = signature
        self.slices = refined_slices


class Callsite:
    def __init__(self, addr) -> None:
        self.addr = addr
        self.functionName = idc.get_func_name(self.addr)
        self.functionStart, self.functionEnd = get_func_boudary(self.addr)
        self.signature = []
        self.slices = []


    def _BackwardSliceOnRegs(self, reg_count: dict, reg_map: dict) -> Tuple[list, list]:

        ret_slice = self._ForwardRetSlice()


        slices = []
        signature = []
        call_ins_count = 0 
        j_ins_count = 0 

        iter = self.addr
        while self.functionStart <= iter:
            flag = False
            iter = idc.prev_head(iter)
            opcode = idc.print_insn_mnem(iter)
            if opcode.startswith("nop"):
                continue

            insn,r,w = getDisasmCapstone(iter)

            if opcode.startswith("call"):
                break

            if j_ins_count < j_ins_threshold:
                if is_tail_call(opcode, iter):
                    j_ins_count += 1
                    flag = True
            else:
                break

            for reg in w:
                if not reg in reg_map.keys():
                    continue
                reg = reg_map[reg]
                if reg_map[reg] == "rax": 
                    continue
                if reg_count[reg_map[reg]] > reg_rw_threshold: 
                    continue

                reg_count[reg_map[reg]] += 1
                flag = True

            if flag:
                slices.append(insn)

        slices.reverse()
        slices.append("callsite callee")
        slices.extend(ret_slice)

        float_reg_count = {}
        for key in reg_count:
            if key.startswith("zmm"):
                float_reg_count[key] = reg_count[key]

        for reg in reg_count:
            if reg_count[reg] > 0:
                signature.append(reg)
        for reg in float_reg_count:
            if float_reg_count[reg] > 0 and (reg not in signature):
                signature.append(reg)

        if len(ret_slice) > 0 and ("rax" not in signature):
            signature.append("rax")

        return (signature, slices)


    def callsiteslice(self):
        reg_count = {"rdi":0,"rsi":0,"rdx":0,"rcx":0,"r8":0,"r9":0,"rsp":0,"rbp":0,"rax":0,"zmm0":0,"zmm1":0,"zmm2":0,"zmm3":0}
        signature,raw_slices = self._BackwardSliceOnRegs(reg_count, init_reg_map)

        new_reg_count = {}
        new_reg_map = {}
        for reg in signature:
            new_reg_count[reg] = 0
            for key in reversed_reg_map[reg]:
                new_reg_map[key] = reg

        signature,refined_slices = self._BackwardSliceOnRegs(new_reg_count, new_reg_map)

        self.signature = signature
        self.slices = refined_slices



    def _ForwardRetSlice(self) -> list:
        reg_count = {"rax":0} 

        slices = []
        call_ins_count = 0
        j_ins_count = 0
        addr = self.addr
        while self.functionStart <= addr < self.functionEnd:
            flag = False
            addr = idc.next_head(addr)

            opcode = idc.print_insn_mnem(addr)
            if opcode.startswith("nop"):
                addr = idc.next_head(addr)
                continue

            insn,r,w = getDisasmCapstone(addr)
            if opcode.startswith("call"):
                break

            for reg in r: 
                if not reg in init_reg_map.keys(): 
                    continue
                if init_reg_map[reg] != "rax": 
                    continue

                reg_count["rax"] += 1 
                flag = True

            if flag:
                slices.append(insn)

            if reg_count["rax"] > reg_rw_threshold: 
                break

        return slices


if __name__ == '__main__':
    if len(idc.ARGV) < 2:
        print('\n\nGenerating AICT Eval Data')
        print('\tNeed to specify the output dir')
        print('\tUsage: /path/to/ida -A -Llog/{}.log -S"{} <output_dir>" /path/to/binary\n\n'.format(ida_nalt.get_root_filename(), idc.ARGV[0]))
        ida_pro.qexit(1)

    output_dir = idc.ARGV[1]

    AT_FUNCTIONS = []
    ICALLSITES = []
    text_func_count = 0
    for func in tqdm(idautils.Functions(), desc="Slicing..."):

        func_name = idc.get_func_name(func)
        demangle_name = idc.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
        if demangle_name:
            func_name = demangle_name
        if (func < plt_end and func >= plt_start) or (func < plt_got_end and func >= plt_got_start):
            func = getRealAddr(func)

        if text_start<= func < text_end:
            text_func_count += 1
            if list(idautils.DataRefsTo(func)):
                num_insns = get_num_insns(func)
                if num_insns < SKIP_THRESHOLD: 
                    print('Small function:', func_name, num_insns)
                    continue
                if not func_name in at_blacklist:
                    this_func = Callee(func)
                    this_func.calleeSlice()
                    AT_FUNCTIONS.append((set(this_func.signature), this_func.slices))

            for (startea, endea) in idautils.Chunks(func):
                for head in idautils.Heads(startea, endea):
                    opcode = idc.print_insn_mnem(head)

                    if opcode == "call":
                        optype = idc.get_operand_type(head, 0)
                        callee_ea = idc.get_operand_value(head, 0)

                        if 1<= optype < 5: 
                            callsite = Callsite(head)
                            callsite.callsiteslice()
                            callsite_slices = callsite.slices
                            callsite_sig = set(callsite.signature)
                            ICALLSITES.append((callsite_sig, callsite_slices))

    callsite_idx = 0
    output_dir = idc.ARGV[1]
    for callsite_sig, callsite_slices in tqdm(ICALLSITES, desc="Storing slices..."):
        all_pairs = ''
        for callee_sig, callee_slices in AT_FUNCTIONS:
            all_pairs += '{}|{} -> {}|{}\n'.format(
                                                    '.'.join(callsite_sig),
                                                    '\t'.join(callsite_slices),
                                                    '.'.join(callee_sig),
                                                    '\t'.join(callee_slices)
                                                    )
        with open(os.path.join(output_dir, '{}_{}.slice'.format(ida_nalt.get_root_filename(), callsite_idx)),'w') as f:
            f.write(all_pairs)
            callsite_idx += 1

    ida_pro.qexit(0)
