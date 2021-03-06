#include <algorithm>

#include "bb.h"
#include "edge.h"
#include "insn.h"
#include "cfg.h"
#include "log.h"
#include "nucleus.h"
#include "export.h"

int
export_bin2ida(std::string& fname, Binary* bin,
               std::list<DisasmSection>* disasm, CFG* cfg) {
  FILE*    f;
  uint64_t entry;
  size_t   i;

  f = fopen(fname.c_str(), "w");
  if (!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return -1;
  }

  fprintf(f, "\"\"\"\n");
  fprintf(f, "Script generated by %s\n", NUCLEUS_VERSION);
  fprintf(f, "\"\"\"\n");
  fprintf(f, "\n");
  fprintf(f, "import idaapi\n");
  fprintf(f, "import idautils\n");
  fprintf(f, "import idc\n");
  fprintf(f, "\n");
  fprintf(f, "idaapi.autoWait()\n");
  fprintf(f, "\n");
  fprintf(f, "def mark_functions():\n");
  fprintf(f, "    functions = [\n");
  i = 0;
  for (auto& func : cfg->functions) {
    if (func.entry.empty())
      continue;
    entry = func.entry.front()->start;
    if (!(i % 5))
      fprintf(f, "        ");
    fprintf(f, "0x%jx, ", entry);
    if (!(++i % 5))
      fprintf(f, "\n");
  }
  fprintf(f, "    ]\n");
  fprintf(f, "    for seg in idautils.Segments():\n");
  fprintf(f,
          "        if idaapi.segtype(idc.SegStart(seg)) != idaapi.SEG_CODE:\n");
  fprintf(f, "            continue\n");
  fprintf(f, "        for f in idautils.Functions(idc.SegStart(seg), "
             "idc.SegEnd(seg)):\n");
  fprintf(f, "            print 'nucleus: deleting function 0x%%x' %% (f)\n");
  fprintf(f, "            idc.DelFunction(f)\n");
  fprintf(f, "    for f in functions:\n");
  fprintf(f, "        print 'nucleus: defining function 0x%%x' %% (f)\n");
  fprintf(f, "        if idc.MakeCode(f):\n");
  fprintf(f, "            idc.MakeFunction(f)\n");
  fprintf(f, "\n");
  fprintf(f, "mark_functions()\n");

  fclose(f);

  return 0;
}

int
export_bin2binja(std::string& fname, Binary* bin,
                 std::list<DisasmSection>* disasm, CFG* cfg) {
  FILE*    f;
  uint64_t entry;
  size_t   i;

  f = fopen(fname.c_str(), "w");
  if (!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return -1;
  }

  fprintf(f, "\"\"\"\n");
  fprintf(f, "Script generated by %s\n", NUCLEUS_VERSION);
  fprintf(f, "\"\"\"\n");
  fprintf(f, "\n");
  fprintf(f, "import binaryninja\n");
  fprintf(f, "\n");
  fprintf(f, "def mark_functions():\n");
  fprintf(f, "    functions = [\n");
  i = 0;
  for (auto& func : cfg->functions) {
    if (func.entry.empty())
      continue;
    entry = func.entry.front()->start;
    if (!(i % 5))
      fprintf(f, "        ");
    fprintf(f, "0x%jx, ", entry);
    if (!(++i % 5))
      fprintf(f, "\n");
  }
  fprintf(f, "    ]\n");
  fprintf(f, "    for f in bv.functions:\n");
  fprintf(f, "        bv.remove_function(f)\n");
  fprintf(f, "    for f in functions:\n");
  fprintf(f, "        print 'nucleus: defining function 0x%%x' %% (f)\n");
  fprintf(f, "        bv.add_function(f)\n");
  fprintf(f, "\n");
  fprintf(f, "mark_functions()\n");

  fclose(f);

  return 0;
}

int
export_bin2r2(std::string& fname, Binary* bin, std::list<DisasmSection>* disasm,
              CFG* cfg) {
  FILE*    f;
  size_t   i;
  unsigned offset;

  f = fopen(fname.c_str(), "w");
  if (!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return -1;
  }

  fprintf(f, "\"\"\"\n");
  fprintf(f, "# Script generated by %s\n", NUCLEUS_VERSION);
  fprintf(f, "\"\"\"\n");
  fprintf(f, "\n");

  for (auto& func : cfg->functions) {
    if (func.entry.empty()) {
      fprintf(f, "f fcn.%016jx %ju 0x%016jx\n", func.start,
              func.end - func.start, func.start);
      fprintf(f, "af+ 0x%016jx fcn.%016jx f n\n", func.start, func.start);
    } else {
      i = 0;
      for (auto entry_bb : func.entry) {
        offset = 0;
        for (auto& e : entry_bb->ancestors) {
          if (e.type == Edge::EDGE_TYPE_CALL)
            offset = e.offset;
        }
        if (i == 0) {
          func.start = entry_bb->start + offset;
          fprintf(f, "f fcn.%016jx %ju 0x%016jx\n", func.start,
                  (func.end - entry_bb->start), func.start);
          fprintf(f, "af+ 0x%016jx fcn.%016jx f n\n", func.start, func.start);
        }
        i++;
      }
    }

    func.BBs.sort([](BB* a, BB* b) { return BB::comparator(*a, *b); });
    for (auto& bb : func.BBs) {
      fprintf(f, "afb+ 0x%016jx 0x%016jx %ju ", func.start, bb->start,
              bb->end - bb->start);

      auto jump =
          std::find_if(bb->targets.begin(), bb->targets.end(), [](Edge& e) {
            return e.type != Edge::EDGE_TYPE_FALLTHROUGH;
          });
      auto fall =
          std::find_if(bb->targets.begin(), bb->targets.end(), [](Edge& e) {
            return e.type == Edge::EDGE_TYPE_FALLTHROUGH;
          });

      if (jump != bb->targets.end())
        fprintf(f, "0x%016jx ", jump->dst->start);
      else
        fprintf(f, "0xffffffffffffffff ");

      if (fall != bb->targets.end())
        fprintf(f, "0x%016jx n\n", fall->dst->start);
      else
        fprintf(f, "0xffffffffffffffff n\n");

      for (auto& ins : bb->insns) {
        if (ins.flags & Instruction::INS_FLAG_CALL)
          fprintf(f, "afxC 0x%016jx 0x%016jx\n", ins.address, ins.target);
        else if (ins.flags & Instruction::INS_FLAG_JMP)
          fprintf(f, "afxc 0x%016jx 0x%016jx\n", ins.address, ins.target);
      }
    }
  }

  for (auto& func : cfg->functions) {
    if (func.start >= func.BBs.back()->end)
      continue;
    fprintf(f, "afu 0x%016jx @ 0x%016jx\n", func.BBs.back()->end, func.start);
  }

  fclose(f);

  return 0;
}

int
export_cfg2dot(std::string& fname, CFG* cfg) {
  FILE* f;
  BB*   bb;

  f = fopen(fname.c_str(), "w");
  if (!f) {
    print_err("cannot open file '%s' for writing", fname.c_str());
    return -1;
  }

  fprintf(f, "digraph G {\n\n");
  for (auto& kv : cfg->start2bb) {
    bb = kv.second;
    for (auto& e : bb->targets) {
      fprintf(f, "bb_%jx -> bb_%jx [ label=\"%s\" ];\n", e.src->start,
              e.dst->start, e.type2str().c_str());
    }
  }
  fprintf(f, "}\n");

  fclose(f);

  return 0;
}
