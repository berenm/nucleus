#include <capstone/capstone.h>

#include "disasm-aarch64.h"
#include "log.h"

static int
is_cs_nop_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM64_INS_NOP:
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
   * for aarch64 instructions, unlike x86, so we have to do it manually.
   * Once this is implemented, it will suffice to check for the following
   * groups:
   * CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET */

  switch (ins->id) {
  case ARM64_INS_B:
  case ARM64_INS_BR:
  case ARM64_INS_BL:
  case ARM64_INS_BLR:
  case ARM64_INS_CBNZ:
  case ARM64_INS_CBZ:
  case ARM64_INS_TBNZ:
  case ARM64_INS_TBZ:
  case ARM64_INS_RET:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_call_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM64_INS_BL:
  case ARM64_INS_BLR:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_ret_ins(cs_insn* ins) {
  /* ret */
  if (ins->id == ARM64_INS_RET) {
    return 1;
  }

  return 0;
}

static int
is_cs_unconditional_jmp_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM64_INS_B:
    if (ins->detail->arm64.cc != ARM64_CC_INVALID &&
        ins->detail->arm64.cc != ARM64_CC_AL) {
      return 0;
    }
    return 1;
  case ARM64_INS_BR:
    return 1;
  default:
    return 0;
  }
}

static int
is_cs_conditional_cflow_ins(cs_insn* ins) {
  switch (ins->id) {
  case ARM64_INS_B:
    if (ins->detail->arm64.cc != ARM64_CC_AL) {
      return 1;
    }
    return 0;
  case ARM64_INS_CBNZ:
  case ARM64_INS_CBZ:
  case ARM64_INS_TBNZ:
  case ARM64_INS_TBZ:
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
  switch (ins->id) {
  case ARM64_INS_BR:
  case ARM64_INS_BLR:
    return 1;
  default:
    return 0;
  }
}

int
nucleus_disasm_bb_aarch64(Binary* bin, DisasmSection* dis, BB* bb) {
  int init, ret, jmp, indir, cflow, cond, call, nop, only_nop, priv, trap,
      ndisassembled;
  csh            cs_dis;
  cs_mode        cs_mode_flags;
  cs_arm64_op*   cs_op;
  const uint8_t* pc;
  uint64_t       pc_addr, offset;
  size_t         i, j, n;
  Instruction    insn;

  init = 0;
  switch (bin->bits) {
  case 64:
    cs_mode_flags = (cs_mode)(CS_MODE_ARM);
    break;
  default:
    print_err("unsupported bit width %u for architecture %s", bin->bits,
              bin->arch_str.c_str());
    goto fail;
  }

  if (cs_open(CS_ARCH_ARM64, cs_mode_flags, &cs_dis) != CS_ERR_OK) {
    print_err("failed to initialize libcapstone");
    goto fail;
  }
  init = 1;
  cs_option(cs_dis, CS_OPT_DETAIL, CS_OPT_ON);

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
  while (cs_disasm_iter(cs_dis, &pc, &n, &pc_addr, &insn)) {
    if (insn.id == ARM64_INS_INVALID) {
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

    for (i = 0; i < insn.detail.arm64.op_count; i++) {
      cs_op = &insn.detail.arm64.operands[i];
      if (cflow && cs_op->type == ARM64_OP_MEM)
        insn.flags |= Instruction::INS_FLAG_INDIRECT;
    }

    if (cflow) {
      for (j = 0; j < insn.detail.arm64.op_count; j++) {
        cs_op = &insn.detail.arm64.operands[j];
        if (cs_op->type == ARM64_OP_IMM) {
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
  if (init) {
    cs_close(&cs_dis);
  }
  return ret;
}
