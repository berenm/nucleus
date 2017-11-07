#include <capstone/capstone.h>

#include "disasm-mips.h"
#include "log.h"

static int
is_cs_nop_ins(cs_insn* ins) {
  switch (ins->id) {
  case MIPS_INS_NOP:
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
is_cs_cflow_ins(cs_insn* ins) {
  /* XXX: Capstone does not provide information for all generic groups
   * for mips instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following
   * groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch (ins->id) {
  case MIPS_INS_J:
  case MIPS_INS_JR:
  case MIPS_INS_B:
  case MIPS_INS_BAL:
  case MIPS_INS_JAL:
  case MIPS_INS_JALR:
  case MIPS_INS_BEQ:
  case MIPS_INS_BNE:
  case MIPS_INS_BGTZ:
  case MIPS_INS_BGEZ:
  case MIPS_INS_BNEZ:
  case MIPS_INS_BEQZ:
  case MIPS_INS_BLEZ:
  case MIPS_INS_BLTZ:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_call_ins(cs_insn* ins) {
  switch (ins->id) {
  case MIPS_INS_BAL:
  case MIPS_INS_JAL:
  case MIPS_INS_JALR:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_ret_ins(cs_insn* ins) {
  /* jr ra */
  if (ins->id == MIPS_INS_JR &&
      ins->detail->mips.operands[0].type == MIPS_OP_REG &&
      ins->detail->mips.operands[0].reg == MIPS_REG_RA) {
    return 1;
  }

  return 0;
}

static int
is_cs_unconditional_jmp_ins(cs_insn* ins) {
  switch (ins->id) {
  case MIPS_INS_B:
  case MIPS_INS_J:
    return 1;
  case MIPS_INS_JR:
    if (ins->detail->mips.operands[0].reg != MIPS_REG_RA) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}

static int
is_cs_conditional_cflow_ins(cs_insn* ins) {
  switch (ins->id) {
  case MIPS_INS_BEQ:
  case MIPS_INS_BNE:
  case MIPS_INS_BGTZ:
  case MIPS_INS_BGEZ:
  case MIPS_INS_BNEZ:
  case MIPS_INS_BEQZ:
  case MIPS_INS_BLEZ:
  case MIPS_INS_BLTZ:
    return 1;
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

static int
is_cs_indirect_ins(cs_insn* ins) {
  /* jr rN */
  if (ins->id == MIPS_INS_JR &&
      ins->detail->mips.operands[0].type == MIPS_OP_REG &&
      ins->detail->mips.operands[0].reg != MIPS_REG_RA) {
    return 1;
  }

  /* jalr rN */
  if (ins->id == MIPS_INS_JALR) {
    return 1;
  }

  return 0;
}

int
nucleus_disasm_bb_mips(Binary* bin, DisasmSection* dis, BB* bb) {
  int ret, jmp, cflow, indir, cond, call, nop, only_nop, priv, trap,
      ndisassembled;
  cs_mips_op*    cs_op;
  const uint8_t* pc;
  uint64_t       pc_addr, offset;
  size_t         i, j, n;
  Instruction*   last_cflow;
  Instruction    insn;

  last_cflow = nullptr;

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
    if (insn.id == MIPS_INS_INVALID) {
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
    if (!last_cflow && !only_nop && nop)
      break;
    if (!last_cflow && only_nop && !nop)
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

    for (i = 0; i < insn.detail.mips.op_count; i++) {
      cs_op = &insn.detail.mips.operands[i];
      if (cflow && cs_op->type == MIPS_OP_MEM)
        insn.flags |= Instruction::INS_FLAG_INDIRECT;
    }

    if (cflow) {
      for (j = 0; j < insn.detail.mips.op_count; j++) {
        cs_op = &insn.detail.mips.operands[j];
        if (cs_op->type == MIPS_OP_IMM) {
          insn.target = cs_op->imm;
        }
      }
    }

    /* end of basic block occurs after delay slot of cflow instructions */
    if (last_cflow) {
      insn.flags        = last_cflow->flags;
      insn.target       = last_cflow->target;
      last_cflow->flags = 0;
      break;
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
      last_cflow = &insn;
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
