#ifndef NUCLEUS_INSN_H
#define NUCLEUS_INSN_H

#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>

#include <string>
#include <vector>

#include "edge.h"

struct Instruction : cs_insn {
  enum InstructionFlags {
    INS_FLAG_CFLOW    = 0x001,
    INS_FLAG_COND     = 0x002,
    INS_FLAG_INDIRECT = 0x004,
    INS_FLAG_JMP      = 0x008,
    INS_FLAG_CALL     = 0x010,
    INS_FLAG_RET      = 0x020,
    INS_FLAG_NOP      = 0x040,
    INS_FLAG_DATA     = 0x080,
  };

  Instruction()
      : cs_insn{}, detail{}, target(0), flags(0), invalid(false),
        privileged(false), trap(false) {
    cs_insn::detail = &detail;
  }
  Instruction(const Instruction& i)
      : cs_insn{i}, detail(i.detail), target(i.target), flags(i.flags),
        invalid(i.invalid), privileged(i.privileged), trap(i.trap) {
    cs_insn::detail = &detail;
  }

  void           print(FILE* out);
  Edge::EdgeType edge_type();

  cs_detail      detail;
  uint64_t       target;
  unsigned short flags;
  bool           invalid;
  bool           privileged;
  bool           trap;
};

#endif /* NUCLEUS_INSN_H */
