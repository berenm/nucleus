#include <stdio.h>

#include "edge.h"
#include "insn.h"

void
Instruction::print(FILE* out) {
  fprintf(out, "  0x%016jx %s%s%s%s%s%s%s%s  %s\t%s\n", address,
          flags & INS_FLAG_CFLOW ? "f" : "-", flags & INS_FLAG_COND ? "c" : "-",
          flags & INS_FLAG_INDIRECT ? "i" : "-",
          flags & INS_FLAG_JMP ? "j" : "-", flags & INS_FLAG_CALL ? "x" : "-",
          flags & INS_FLAG_RET ? "r" : "-", flags & INS_FLAG_NOP ? "n" : "-",
          flags & INS_FLAG_DATA ? "d" : "-", mnemonic, op_str);
}

Edge::EdgeType
Instruction::edge_type() {
  if (flags & INS_FLAG_JMP) {
    return (flags & INS_FLAG_INDIRECT) ? Edge::EDGE_TYPE_JMP_INDIRECT
                                       : Edge::EDGE_TYPE_JMP;
  } else if (flags & INS_FLAG_CALL) {
    return (flags & INS_FLAG_INDIRECT) ? Edge::EDGE_TYPE_CALL_INDIRECT
                                       : Edge::EDGE_TYPE_CALL;
  } else if (flags & INS_FLAG_DATA) {
    return (flags & INS_FLAG_INDIRECT) ? Edge::EDGE_TYPE_DATA_INDIRECT
                                       : Edge::EDGE_TYPE_DATA;
  } else if (flags & INS_FLAG_RET) {
    return Edge::EDGE_TYPE_RET;
  } else {
    return Edge::EDGE_TYPE_NONE;
  }
}
