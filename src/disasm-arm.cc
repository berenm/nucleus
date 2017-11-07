#include <capstone/capstone.h>

#include "disasm-arm.h"
#include "log.h"

static int
is_cs_nop_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM_INS_NOP:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_trap_ins(cs_insn* ins) {
  switch (ins->id) {
  /* XXX: todo */
  default:
    return 0;
  }
}

static int
is_cs_call_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM_INS_BL:
  case ARM_INS_BLX:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_ret_ins(cs_insn* ins) {
  size_t i;

  /* bx lr */
  if (ins->id == ARM_INS_BX && ins->detail->arm.op_count == 1 &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_LR) {
    return 1;
  }

  /* ldmfd sp!, {..., pc} */
  if (ins->id == ARM_INS_POP) {
    for (i = 0; i < ins->detail->arm.op_count; i++) {
      if (ins->detail->arm.operands[i].type == ARM_OP_REG &&
          ins->detail->arm.operands[i].reg == ARM_REG_PC) {
        return 1;
      }
    }
  }

  /* mov pc, lr */
  if (ins->id == ARM_INS_MOV &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_PC &&
      ins->detail->arm.operands[1].type == ARM_OP_REG &&
      ins->detail->arm.operands[1].reg == ARM_REG_LR) {
    return 1;
  }

  return 0;
}

static int
is_cs_unconditional_jmp_ins(cs_insn* ins) {
  /* b rN */
  if (ins->id == ARM_INS_B && ins->detail->arm.cc == ARM_CC_AL) {
    return 1;
  }

  /* mov pc, rN */
  if (ins->id == ARM_INS_MOV &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_PC &&
      ins->detail->arm.operands[1].type == ARM_OP_REG &&
      ins->detail->arm.operands[1].reg != ARM_REG_LR) {
    return 1;
  }

  /* ldrls pc, {...} */
  if (ins->id == ARM_INS_LDR &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_PC) {
    return 1;
  }

  return 0;
}

static int
is_cs_conditional_cflow_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM_INS_B:
  case ARM_INS_BL:
  case ARM_INS_BLX:
    if (ins->detail->arm.cc != ARM_CC_AL) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}

static int
is_cs_cflow_ins(cs_insn* ins) {
  size_t i;

  /* XXX: Capstone does not provide information for all generic groups
   * for arm instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following
   * groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  if (is_cs_unconditional_jmp_ins(ins) || is_cs_conditional_cflow_ins(ins) ||
      is_cs_call_ins(ins) || is_cs_ret_ins(ins)) {
    return 1;
  }

  return 0;
}

static int
is_cs_indirect_ins(cs_insn* ins) {
  /* mov pc, rN */
  if (ins->id == ARM_INS_MOV &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_PC &&
      ins->detail->arm.operands[1].type == ARM_OP_REG &&
      ins->detail->arm.operands[1].reg != ARM_REG_LR) {
    return 1;
  }

  /* ldrls pc, {...} */
  if (ins->id == ARM_INS_LDR &&
      ins->detail->arm.operands[0].type == ARM_OP_REG &&
      ins->detail->arm.operands[0].reg == ARM_REG_PC) {
    return 1;
  }

  switch (ins->id) {
  case ARM_INS_BX:
  case ARM_INS_BLX:
  case ARM_INS_BXJ:
    if (ins->detail->arm.operands[0].type == ARM_OP_REG &&
        ins->detail->arm.operands[0].reg == ARM_REG_PC) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}

static int
is_cs_privileged_ins(cs_insn* ins) {
  switch (ins->id) {
  /* XXX: todo */
  default:
    return 0;
  }
}

int
nucleus_disasm_bb_arm(Binary* bin, DisasmSection* dis, BB* bb) {
  int ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap,
      ndisassembled;
  cs_arm_op*     cs_op;
  const uint8_t* pc;
  uint64_t       pc_addr, offset;
  size_t         i, j, n;
  Instruction    insn;

  offset = bb->start - dis->section->vma;
  if ((bb->start < dis->section->vma) || (offset >= dis->section->size)) {
    print_err("basic block address points outside of section '%s'",
              dis->section->name.c_str());
    goto fail;
  }

  pc            = dis->section->bytes + offset;
  n             = dis->section->size - offset;
  pc_addr       = bb->start;
  bb->end       = bb->start;
  bb->section   = dis->section;
  ndisassembled = 0;
  only_nop      = 0;
  while (cs_disasm_iter(bin->cs_dis, &pc, &n, &pc_addr, &insn)) {
    if (insn.id == ARM_INS_INVALID) {
      bb->invalid = 1;
      bb->end += 1;
      break;
    }
    if (!insn.size) {
      break;
    }

    trap = is_cs_trap_ins(&insn);
    nop  = is_cs_nop_ins(&insn);
    ret  = is_cs_ret_ins(&insn);
    jmp  = is_cs_unconditional_jmp_ins(&insn) ||
          is_cs_conditional_cflow_ins(&insn);
    cond  = is_cs_conditional_cflow_ins(&insn);
    cflow = is_cs_cflow_ins(&insn);
    call  = is_cs_call_ins(&insn);
    priv  = is_cs_privileged_ins(&insn);
    indir = is_cs_indirect_ins(&insn);

    if (!ndisassembled && nop)
      only_nop = 1; /* group nop instructions together */
    if (!only_nop && nop)
      break;
    if (only_nop && !nop)
      break;

    ndisassembled++;

    insn.privileged = priv;
    insn.trap       = trap;
    insn.flags      = 0;
    if (nop)
      insn.flags |= Instruction::INS_FLAG_NOP;
    if (ret)
      insn.flags |= Instruction::INS_FLAG_RET;
    if (jmp)
      insn.flags |= Instruction::INS_FLAG_JMP;
    if (cond)
      insn.flags |= Instruction::INS_FLAG_COND;
    if (cflow)
      insn.flags |= Instruction::INS_FLAG_CFLOW;
    if (call)
      insn.flags |= Instruction::INS_FLAG_CALL;
    if (indir)
      insn.flags |= Instruction::INS_FLAG_INDIRECT;

    for (i = 0; i < insn.detail.arm.op_count; i++) {
      cs_op = &insn.detail.arm.operands[i];
      if (cflow && cs_op->type == ARM_OP_MEM)
        insn.flags |= Instruction::INS_FLAG_INDIRECT;
    }

    if (cflow) {
      for (j = 0; j < insn.detail.arm.op_count; j++) {
        cs_op = &insn.detail.arm.operands[j];
        if (cs_op->type == ARM_OP_IMM) {
          insn.target = cs_op->imm;
        }
      }
    }

    bb->end += insn.size;
    bb->insns.push_back(insn);
    if (priv) {
      bb->privileged = true;
    }
    if (nop) {
      bb->padding = true;
    }
    if (trap) {
      bb->trap = true;
    }

    if (cflow) {
      /* end of basic block */
      break;
    }
  }

  if (!ndisassembled) {
    bb->invalid = 1;
    bb->end += 1; /* ensure forward progress */
  }

  ret = ndisassembled;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}
