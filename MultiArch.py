from bincraft import Sleigh
from enum import Enum
from multiprocessing import Process
from multiprocessing import Manager
from multiprocessing import Pool
from scipy.interpolate import lagrange


class Arch(Enum):
    """ Arch Type"""

    arch_6502 = 0
    arch_6805 = 0
    arch_6809 = 0
    arch_8048 = 0
    arch_8051 = 0
    arch_8085 = 0
    arch_68020 = 0
    arch_68030 = 0
    arch_68040 = 0
    arch_80251 = 0
    arch_80390 = 0
    x86 = 0
    x86_64 = 0
    ARM5_le = 2
    ARM5t_be = 1
    ARM6_le = 2
    ARM6_be = 1
    ARM7_le = 2
    ARM7_be = 1
    ARM8_le = 2
    ARM8_be = 1
    AARCH64 = 2
    AARCH64BE = 1
    Dalvik = 0
    HC05 = 0
    HC08 = 0
    HCS08 = 0
    HCS12 = 0
    m8c = 0
    MCS96 = 0
    mips32le = 2
    mips32be = 1
    mips32R6be = 1
    mips32R6le = 2
    mips64be = 1
    mips64le = 2
    mx51 = 0
    ppc_32_4xx_be = 1
    ppc_32_4xx_le = 2
    ppc_32_be = 1
    ppc_32_le = 2
    ppc_64_be = 1
    ppc_64_le = 2

    def __str__(self):
        return self.name

    def __int__(self):
        return self.value


def multi_progress_find(op, arch, flag, start, end, valid_inst):
    """Multi-process lookup opcode.

    Args:
      op: A p-code operation, e.g. BRANCH, CALL, COPY etc.
      arch: Type of architecture, e.g. x86, AARCH64, ARM8_le etc.
      flag: Used to set the code type for brute force disassembly code.
      start: Used to set the point of brute force start for instruction code
      end: Used to set the point of brute force end for instruction code
      valid_inst: Whether to output a valid instruction.

    Returns:
      Return the instruction set that matches the opcode and valid instruction.For
      example:
      ['0x4c']
      ['0x40', '0x41', '0x45', '0x46', '0x48', '0x49', '0x4a', '0x4c', '0x4d', '0x4e', '0x50', '0x51', '0x55']
    """

    inst_list = []
    valid_inst_list = []
    for i in range(start, end):
        if int(flag) == 0:
            code = [i]
        elif int(flag) == 1:
            code = [i, 0x0, 0x0, 0x0]
        elif int(flag) == 2:
            code = [0x0, 0x0, 0x0, i]

        sleigh = Sleigh(arch, code)

        try:
            for asm in sleigh.disasm(0):
                if valid_inst:
                    valid_inst_list.append(hex(i))
                pcodes = asm.pcodes()
                pcode = PcodeInterpreter(pcodes)
                result = pcode.find(op)
                if result:
                    inst_list.append(hex(i))
                    break
        except:
            pass

    if valid_inst:
        return inst_list, valid_inst_list
    else:
        return inst_list


def match_inst(op, valid_inst=False):
    """Match the corresponding instruction set according to the opcode.

        Args:
          op: A p-code operation, e.g. BRANCH, CALL, COPY etc.
          valid_inst: Whether to obtain a valid instruction set, the default is False

        Returns:
          Return the instruction set that matches the opcode or matching valid instructions dict.For
          example:
          {'x86': {'0xe9': {'offset': ' 1*offset + 3', 'arch': []}}}
    """

    inst_dic = {}
    valid_inst_dict = {}
    for architecture, flag in Arch.__members__.items():
        pool = Pool(processes=4)
        obj = []

        arch = architecture.replace("arch_", "")
        print("try arch: {}".format(arch))
        if architecture == "x86_64":
            arch = "x86-64"
        for i in range(4):
            result = pool.apply_async(multi_progress_find, (op, arch, flag, 64 * i, 64 * (i + 1), valid_inst,))
            obj.append(result)
        pool.close()
        pool.join()

        for res in obj:
            if valid_inst:
                inst, valid_inst = res.get()
            else:
                inst = res.get()

            if inst:
                inst_dic[arch] = inst

            if valid_inst:
                if arch in valid_inst_dict:
                    valid_inst_list = valid_inst_dict[arch]
                    valid_inst_list.extend(valid_inst)
                    valid_inst_dict[arch] = valid_inst_list
                else:
                    valid_inst_dict[arch] = valid_inst

    if valid_inst:
        branch_dict = {}
        for branch_arch, branch_inst_list in inst_dic.items():
            for branch_inst in branch_inst_list:
                rel_offset = offset(branch_inst, branch_arch)
                if branch_arch in branch_dict:

                    branch_dict_subset = branch_dict[branch_arch]
                    branch_dict_subset[branch_inst] = {"offset": rel_offset, "arch": []}
                    branch_dict[branch_arch] = branch_dict_subset
                else:
                    branch_dict[branch_arch] = {branch_inst: {"offset": rel_offset, "arch": []}}
                for arch, inst_list in valid_inst_dict.items():
                    if branch_arch != arch and branch_inst in inst_list:
                        compliant_arch = branch_dict[branch_arch][branch_inst]['arch']
                        compliant_arch.append(arch)
                        branch_dict[branch_arch][branch_inst]['arch'] = compliant_arch
        return branch_dict
    else:
        return inst_dic


def get_offset(code, arch):
    sleigh = Sleigh(arch, code)
    for asm in sleigh.disasm(0):
        pcodes = PcodeInterpreter(asm.pcodes())
        offset = int(pcodes.varnode_list()[0]["offset"])

        return offset


def offset(inst, arch):
    """ Calculate the offset via Lagrange.

            Args:
              inst: Instruction of op
              arch: Architecture for calculate

            Returns:
              Return Offset polynomial.For example:

    """
    type_arch = arch
    if type_arch.isdigit():
        type_arch = 'arch_' + arch
    if type_arch == "x86-64":
        type_arch = "x86_64"

    flag = int(Arch[type_arch])

    x = [0x1, 0x2, 0x3]
    y = []

    rel_offset = ""
    if int(flag) == 0:
        for i in x:
            code = [int(inst, 16), i]
            y.append(get_offset(code, arch))
        rel_offset = str(lagrange(x, y)).replace(' x', '*offset').replace("\n", "")
    elif int(flag) == 1:
        for i in x:
            code = [int(inst, 16), 0x0, 0x0, i]
            y.append(get_offset(code, arch))
        rel_offset = str(lagrange(x, y)).replace(' x', '*offset').replace("\n", "")
    elif int(flag) == 2:
        for i in x:
            code = [i, 0x0, 0x0, int(inst, 16)]
            y.append(get_offset(code, arch))
        rel_offset = str(lagrange(x, y)).replace(' x', '*offset').replace("\n", "")
    return rel_offset


class PcodeInterpreter:
    """ Pcode interpreter class

    Used to parse pcode type.

    Attributes:
        pcodes: list of pcode.
        varnode: dict of varnode.
    """
    __pcodes = []
    __varnode = {}
    __varnode_list = []

    def __init__(self, pcodes):
        self.__pcodes = pcodes
        self.__varnode_list = self.varnode(pcodes)

    def find(self, op):
        """Match according to opcode."""
        for pcode in self.__pcodes:
            opcode = pcode.opcode()
            if op == opcode:
                return pcode
            else:
                return []

    def varnode(self, pcodes):
        """Inits varnode"""
        pcode_list = []
        for pcode in self.__pcodes:
            str_varnode = str(pcode.vars()[0]).split(":")
            self.__varnode["offset"] = str_varnode[1]
            self.__varnode["space"] = str_varnode[0].split("@")[1].split("(")[0]
            self.__varnode["size"] = str_varnode[0].split("@")[1].split("(")[1].split(")")[0]
            pcode_list.append(self.__varnode)

        return pcode_list

    def varnode_list(self):
        return self.__varnode_list


if __name__ == '__main__':
    branch_dict = match_inst("BRANCH", valid_inst=True)

    print(branch_dict)
    # Test print:
    # {'6502': {'0x4c': {'offset': ' 1*offset', 'arch': ['6805', '6809]}}}
