#include <capstone/capstone.h>

#include "disasm-x86.h"
#include "log.h"

static int
is_cs_nop_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_NOP:
  case X86_INS_FNOP:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_semantic_nop_ins(cs_insn* ins) {
  cs_x86* x86;

  /* XXX: to make this truly platform-independent, we need some real
   * semantic analysis, but for now checking known cases is sufficient */

  x86 = &ins->detail->x86;
  switch (ins->id) {
  case X86_INS_MOV:
    /* mov reg,reg */
    if ((x86->op_count == 2) && (x86->operands[0].type == X86_OP_REG) &&
        (x86->operands[1].type == X86_OP_REG) &&
        (x86->operands[0].reg == x86->operands[1].reg)) {
      return 1;
    }
    return 0;
  case X86_INS_XCHG:
    /* xchg reg,reg */
    if ((x86->op_count == 2) && (x86->operands[0].type == X86_OP_REG) &&
        (x86->operands[1].type == X86_OP_REG) &&
        (x86->operands[0].reg == x86->operands[1].reg)) {
      return 1;
    }
    return 0;
  case X86_INS_LEA:
    /* lea    reg,[reg + 0x0] */
    if ((x86->op_count == 2) && (x86->operands[0].type == X86_OP_REG) &&
        (x86->operands[1].type == X86_OP_MEM) &&
        (x86->operands[1].mem.segment == X86_REG_INVALID) &&
        (x86->operands[1].mem.base == x86->operands[0].reg) &&
        (x86->operands[1].mem.index == X86_REG_INVALID)
        /* mem.scale is irrelevant since index is not used */
        && (x86->operands[1].mem.disp == 0)) {
      return 1;
    }
    /* lea    reg,[reg + eiz*x + 0x0] */
    if ((x86->op_count == 2) && (x86->operands[0].type == X86_OP_REG) &&
        (x86->operands[1].type == X86_OP_MEM) &&
        (x86->operands[1].mem.segment == X86_REG_INVALID) &&
        (x86->operands[1].mem.base == x86->operands[0].reg) &&
        (x86->operands[1].mem.index == X86_REG_EIZ)
        /* mem.scale is irrelevant since index is the zero-register */
        && (x86->operands[1].mem.disp == 0)) {
      return 1;
    }
    return 0;
  default:
    return 0;
  }
}

static int
is_cs_trap_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_INT3:
  case X86_INS_UD2:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_cflow_group(uint8_t g) {
  return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) ||
         (g == CS_GRP_IRET);
}

static int
is_cs_cflow_ins(cs_insn* ins) {
  size_t i;

  for (i = 0; i < ins->detail->groups_count; i++) {
    if (is_cs_cflow_group(ins->detail->groups[i])) {
      return 1;
    }
  }

  return 0;
}

static int
is_cs_call_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_CALL:
  case X86_INS_LCALL:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_ret_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_RET:
  case X86_INS_RETF:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_unconditional_jmp_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_JMP:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_conditional_cflow_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_JAE:
  case X86_INS_JA:
  case X86_INS_JBE:
  case X86_INS_JB:
  case X86_INS_JCXZ:
  case X86_INS_JECXZ:
  case X86_INS_JE:
  case X86_INS_JGE:
  case X86_INS_JG:
  case X86_INS_JLE:
  case X86_INS_JL:
  case X86_INS_JNE:
  case X86_INS_JNO:
  case X86_INS_JNP:
  case X86_INS_JNS:
  case X86_INS_JO:
  case X86_INS_JP:
  case X86_INS_JRCXZ:
  case X86_INS_JS:
    return 1;
  case X86_INS_JMP:
  default:
    return 0;
  }
}

static int
is_cs_privileged_ins(cs_insn* ins) {
  switch (ins->id) {
  case X86_INS_HLT:
  case X86_INS_IN:
  case X86_INS_INSB:
  case X86_INS_INSW:
  case X86_INS_INSD:
  case X86_INS_OUT:
  case X86_INS_OUTSB:
  case X86_INS_OUTSW:
  case X86_INS_OUTSD:
  case X86_INS_RDMSR:
  case X86_INS_WRMSR:
  case X86_INS_RDPMC:
  case X86_INS_RDTSC:
  case X86_INS_LGDT:
  case X86_INS_LLDT:
  case X86_INS_LTR:
  case X86_INS_LMSW:
  case X86_INS_CLTS:
  case X86_INS_INVD:
  case X86_INS_INVLPG:
  case X86_INS_WBINVD:
    return 1;
  default:
    return 0;
  }
}

int
nucleus_disasm_bb_x86(Binary* bin, DisasmSection* dis, BB* bb) {
  int ret, jmp, cflow, cond, call, nop, only_nop, priv, trap, ndisassembled;
  cs_x86_op*     cs_op;
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
    if (insn.id == X86_INS_INVALID) {
      bb->invalid = 1;
      bb->end += 1;
      break;
    }
    if (!insn.size) {
      break;
    }

    trap = is_cs_trap_ins(&insn);
    nop =
        is_cs_nop_ins(&insn)
        /* Visual Studio sometimes places semantic nops at the function start */
        || (is_cs_semantic_nop_ins(&insn) && (bin->type != Binary::BIN_TYPE_PE))
        /* Visual Studio uses int3 for padding */
        || (trap && (bin->type == Binary::BIN_TYPE_PE));
    ret = is_cs_ret_ins(&insn);
    jmp = is_cs_unconditional_jmp_ins(&insn) ||
          is_cs_conditional_cflow_ins(&insn);
    cond  = is_cs_conditional_cflow_ins(&insn);
    cflow = is_cs_cflow_ins(&insn);
    call  = is_cs_call_ins(&insn);
    priv  = is_cs_privileged_ins(&insn);

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

    for (i = 0; i < insn.detail.x86.op_count; i++) {
      cs_op = &insn.detail.x86.operands[i];
      if (cflow) {
        if (cs_op->type == X86_OP_REG) {
          insn.flags |= Instruction::INS_FLAG_INDIRECT;
        } else if (cs_op->type == X86_OP_MEM) {
          insn.flags |= Instruction::INS_FLAG_INDIRECT;
        }
      }
    }

    for (j = 0; j < insn.detail.x86.op_count; j++) {
      cs_op = &insn.detail.x86.operands[j];
      if ((cs_op->type == X86_OP_IMM) &&
          ((insn.flags & Instruction::INS_FLAG_CFLOW != 0) ||
           ((cs_op->imm >= dis->section->vma) &&
            (cs_op->imm < dis->section->vma + dis->section->size)))) {
        insn.target = cs_op->imm;
        insn.flags |= Instruction::INS_FLAG_DATA;
      } else if ((cs_op->type == X86_OP_MEM) &&
                 ((insn.detail.x86.op_count == 1) || (j > 0)) &&
                 (cs_op->mem.base != X86_REG_ESP) &&
                 (cs_op->mem.base != X86_REG_EBP) &&
                 (cs_op->mem.disp >= dis->section->vma) &&
                 (cs_op->mem.disp < dis->section->vma + dis->section->size)) {
        insn.target = cs_op->mem.disp;
        insn.flags |= Instruction::INS_FLAG_DATA;
        insn.flags |= Instruction::INS_FLAG_INDIRECT;
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
