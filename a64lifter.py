from binaryninja import LowLevelILLabel, LowLevelILFlagCondition
from binaryninja.architecture import Architecture, ArchitectureHook
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import *


#
# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0473e/CJAJIHAD.html
#
# Suffix    Flags                        Meaning
# EQ        Z set                        Equal
# NE        Z clear                      Not equal
# CS or HS  C set                        Higher or same (unsigned >= )
# CC or LO  C clear                      Lower (unsigned < )
# MI        N set                        Negative
# PL        N clear                      Positive or zero
# VS        V set                        Overflow
# VC        V clear                      No overflow
# HI        C set and Z clear            Higher (unsigned >)
# LS        C clear or Z set             Lower or same (unsigned <=)
# GE        N and V the same             Signed >=
# LT        N and V differ               Signed <
# GT        Z clear, N and V the same    Signed >
# LE        Z set, N and V differ        Signed <=
# AL        Any    Always.               This suffix is normally omitted.

#
# https://static.docs.arm.com/ddi0596/a/DDI_0596_ARM_a64_instruction_set_architecture.pdf
#
# // ConditionHolds()
# // ================
#
# // Return TRUE iff COND currently holds
#
# boolean ConditionHolds(bits(4) cond)
#     // Evaluate base condition.
#     case cond<3:1> of
#         when '000' result = (PSTATE.Z == '1'); // EQ or NE
#         when '001' result = (PSTATE.C == '1'); // CS or CC
#         when '010' result = (PSTATE.N == '1'); // MI or PL
#         when '011' result = (PSTATE.V == '1'); // VS or VC
#         when '100' result = (PSTATE.C == '1' && PSTATE.Z == '0');      // HI or LS
#         when '101' result = (PSTATE.N == PSTATE.V);                    // GE or LT
#         when '110' result = (PSTATE.N == PSTATE.V && PSTATE.Z == '0'); // GT or LE
#         when '111' result = TRUE; // AL
#
#    // Condition flag values in the set '111x' indicate always true
#    // Otherwise, invert condition if necessary.
#    if cond<0> == '1' && cond != '1111' then
#        result = !result;
#
#    return result;


def get_il_cond(il, cond):
    if cond == ARM64_CC_EQ:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_E)
    elif cond == ARM64_CC_NE:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_NE)
    elif cond == ARM64_CC_HS:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_UGE)
    elif cond == ARM64_CC_LO:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_ULT)
    elif cond == ARM64_CC_MI:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_ULT)
    elif cond == ARM64_CC_PL:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_UGE)
    # elif cond == ARM64_CC_VS:
    #     return il.flag_condition(LowLevelILFlagCondition.LLFC_O)
    # elif cond == ARM64_CC_VC:
    #     return il.flag_condition(LowLevelILFlagCondition.LLFC_NO)
    elif cond == ARM64_CC_HI:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_UGT)
    elif cond == ARM64_CC_LS:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_ULE)
    elif cond == ARM64_CC_GE:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_SGE)
    elif cond == ARM64_CC_LT:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_SLT)
    elif cond == ARM64_CC_GT:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_SGT)
    elif cond == ARM64_CC_LE:
        return il.flag_condition(LowLevelILFlagCondition.LLFC_SLE)
    # elif cond == ARM64_CC_AL:
    #     return il.const(1, 1)
    else:
        # ARM64_CC_NV = 16
        return None


def set_il_flags(il, nzcv):
    il.append(il.set_flag('n', il.const(0, (nzcv >> 3) & 1)))
    il.append(il.set_flag('z', il.const(0, (nzcv >> 2) & 1)))
    il.append(il.set_flag('c', il.const(0, (nzcv >> 1) & 1)))
    il.append(il.set_flag('v', il.const(0, (nzcv >> 0) & 1)))
    return il


def get_reg_size(insn, op):
    reg_name = insn.reg_name(op.value.reg)
    r = reg_name[0]
    if r == 'x':
        return 8
    elif r == 'w':
        return 4
    else:
        raise Exception("unknown register %s" % r)


def get_reg_name(insn, op):
    if isinstance(op, int):
        return insn.reg_name(op)
    else:
        return insn.reg_name(op.value.reg)


class A64ArchHook(ArchitectureHook):
    def __init__(self, base_arch):
        super(A64ArchHook, self).__init__(base_arch)
        self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self._cs.detail = True

    def get_bn_reg_index(self, insn, op):
        return self.get_reg_index(get_reg_name(insn, op))

    def get_reg_or_zero(self, il, insn, op):
        reg_name = get_reg_name(insn, op)
        if reg_name == 'wzr':
            return il.const(4, 0)
        elif reg_name == 'xzr':
            return il.const(8, 0)
        return il.reg(get_reg_size(insn, op), self.get_reg_index(reg_name))

    def lift(self, addr, data, il, insn):
        if hasattr(self, 'lift_' + insn.mnemonic):
            return getattr(self, 'lift_' + insn.mnemonic)(addr, data, il, insn)
        else:
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

    def get_instruction_low_level_il(self, data, addr, il):
        for insn in self._cs.disasm(data[:4], addr):
            return self.lift(addr, data, il, insn)
        else:
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

    def lift_ccmp(self, addr, data, il, insn):
        rn = insn.operands[0]
        rm = insn.operands[1]

        reg_size = get_reg_size(insn, rn)

        cond = insn.cc

        assert rm.type in (ARM64_OP_REG, ARM64_OP_IMM)

        t = LowLevelILLabel()
        f = LowLevelILLabel()
        e = LowLevelILLabel()
        il_cond = get_il_cond(il, cond)
        if il_cond is None:
            print("0x%x:\t%s\t%s %x" % (insn.address, insn.mnemonic, insn.op_str, cond))
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

        il.append(il.if_expr(il_cond, t, f))

        il.mark_label(f)
        nzcv = data[0] & 0xf
        set_il_flags(il, nzcv)
        il.append(il.goto(e))

        il.mark_label(t)
        if rm.type == ARM64_OP_REG:
            il.append(il.sub(reg_size, self.get_reg_or_zero(il, insn, rn),
                             self.get_reg_or_zero(il, insn, rm), flags='*'))
        elif rm.type == ARM64_OP_IMM:
            il.append(il.sub(reg_size, self.get_reg_or_zero(il, insn, rn),
                             il.const(reg_size, rm.value.imm), flags='*'))
        il.append(il.goto(e))
        il.mark_label(e)
        return 4

    def lift_cinc(self, addr, data, il, insn):
        t = LowLevelILLabel()
        f = LowLevelILLabel()
        e = LowLevelILLabel()

        rd = insn.operands[0]
        rn = insn.operands[1]

        cond = insn.cc

        il_cond = get_il_cond(il, cond)
        if il_cond is None:
            print("0x%x:\t%s\t%s %x" % (insn.address, insn.mnemonic, insn.op_str, cond))
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

        il.append(il.if_expr(il_cond, t, f))

        reg_size = get_reg_size(insn, rd)
        il.mark_label(f)
        il.append(il.set_reg(reg_size, self.get_bn_reg_index(insn, rd),
                             il.reg(reg_size, self.get_bn_reg_index(insn, rn))))
        il.append(il.goto(e))

        il.mark_label(t)
        il.append(il.set_reg(reg_size, self.get_bn_reg_index(insn, rd),
                             il.add(reg_size, self.get_reg_or_zero(il, insn, rn),
                                    il.const(reg_size, 1))))
        il.append(il.goto(e))

        il.mark_label(e)
        return 4

    def lift_ldar(self, addr, data, il, insn):
        rt = insn.operands[0]
        rn = insn.operands[1]

        reg_size = get_reg_size(insn, rt)

        assert rn.type == ARM64_OP_MEM

        il.append(il.set_reg(reg_size, self.get_bn_reg_index(insn, rt),
                             il.load(reg_size, il.reg(reg_size, self.get_bn_reg_index(insn, rn.mem.base)))))

        return 4

    def lift_stlr(self, addr, data, il, insn):
        rt = insn.operands[0]
        rn = insn.operands[1]

        reg_size = get_reg_size(insn, rt)

        assert rn.type == ARM64_OP_MEM

        il.append(il.store(reg_size, il.reg(reg_size, self.get_bn_reg_index(insn, rn.mem.base)),
                           il.reg(reg_size, self.get_bn_reg_index(insn, rt))))
        return 4

    def lift_umull(self, addr, data, il, insn):
        if len(insn.operands) == 3:
            rd = insn.operands[0]
            rn = insn.operands[1]
            rm = insn.operands[2]
            il.append(il.set_reg(8, self.get_bn_reg_index(insn, rd),
                                 il.mult(8, il.reg(4, self.get_bn_reg_index(insn, rn)),
                                         il.reg(4, self.get_bn_reg_index(insn, rm)))))
            return 4
        else:
            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

    def lift_ldrsw(self, addr, data, il, insn):
        rt = insn.operands[0]
        op = insn.operands[1]
        if op.type == ARM64_OP_IMM:
            label = op.value.imm
            il.append(il.set_reg(8, self.get_bn_reg_index(insn, rt),
                                 il.sign_extend(8, il.load(4, il.const_pointer(8, label)))))
            return 4
        else:
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

    def lift_csinc(self, addr, data, il, insn):
        if len(insn.operands) != 3:
            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

        t = LowLevelILLabel()
        f = LowLevelILLabel()
        e = LowLevelILLabel()

        rd = insn.operands[0]
        rn = insn.operands[1]
        rm = insn.operands[2]

        cond = insn.cc
        il_cond = get_il_cond(il, cond)
        if il_cond is None:
            print("0x%x:\t%s\t%s %x" % (insn.address, insn.mnemonic, insn.op_str, cond))
            return super(A64ArchHook, self).get_instruction_low_level_il(data, addr, il)

        il.append(il.if_expr(il_cond, t, f))

        reg_size = get_reg_size(insn, rd)
        il.mark_label(f)
        il.append(il.set_reg(reg_size, self.get_bn_reg_index(insn, rd),
                             il.add(reg_size, self.get_reg_or_zero(il, insn, rm),
                                    il.const(reg_size, 1))))
        il.append(il.goto(e))

        il.mark_label(t)
        il.append(il.set_reg(reg_size, self.get_bn_reg_index(insn, rd),
                             self.get_reg_or_zero(il, insn, rn)))
        il.append(il.goto(e))

        il.mark_label(e)
        return 4


A64ArchHook(Architecture['aarch64']).register()
