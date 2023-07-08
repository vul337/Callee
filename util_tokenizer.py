class asmTokenizer:
    def __init__(self):
        pass

    def tokenize_insn(self,insn):
        '''mov eax, 1 -> mov eax, imm'''
        insn = insn.replace('(', ' ( ')
        insn = insn.replace(')', ' ) ')
        insn = insn.replace('[', ' [ ')
        insn = insn.replace(']', ' ] ')
        insn = insn.replace(',', ' , ')
        insn = insn.replace('*', ' * ')
        insn = insn.replace('+', ' + ')
        insn = insn.replace('-', ' - ')
        insn = insn.replace(':', ' : ')
        ins_split = insn.split()
        while '' in ins_split:
            ins_split.remove('')

        opcode = ins_split[0] 
        operands = ins_split[1:]
        new_insn = ''
        new_insn += opcode + ' '

        for opnd in operands:

            if opnd.isdigit() or opnd.startswith('0x'):# 处理数字
                # print('found digit:',opnd)
                if opcode == 'call' or opcode[0] == 'j':
                    new_opnd = 'addr'
                else:
                    new_opnd = 'num'
            else:
                new_opnd = opnd
            new_insn += new_opnd + ' '

        new_insn = new_insn.strip()
        return new_insn

    def tokenize_doc(self,doc):
        tokenized_doc = ''
        for insn in doc:
            insn = insn.strip()
            if insn:
                tokenized_doc += self.tokenize_insn(insn) + ' '
        tokenized_doc = tokenized_doc.strip()
        return tokenized_doc
