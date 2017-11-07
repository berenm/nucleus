#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <vector>
#include <list>
#include <map>
#include <queue>
#include <algorithm>

#include <capstone/capstone.h>

#include "loader.h"
#include "bb.h"
#include "disasm.h"
#include "strategy.h"
#include "util.h"
#include "options.h"
#include "log.h"

#include "disasm-aarch64.h"
#include "disasm-arm.h"
#include "disasm-mips.h"
#include "disasm-ppc.h"
#include "disasm-x86.h"

/*******************************************************************************
 **                              DisasmSection                                **
 ******************************************************************************/
void
DisasmSection::print_BBs(FILE* out) {
  fprintf(out, "<Section %s %s @0x%016jx (size %ju)>\n\n",
          section->name.c_str(),
          (section->type == Section::SEC_TYPE_CODE) ? "C" : "D", section->vma,
          section->size);
  sort_BBs();
  for (auto& bb : BBs) {
    bb.print(out);
  }
}

void
DisasmSection::sort_BBs() {
  BBs.sort(BB::comparator);
}

/*******************************************************************************
 **                                AddressMap                                 **
 ******************************************************************************/
void
AddressMap::print_regions(FILE* out) {
  for (auto it = regions.begin(), end = regions.end(); it != end; ++it) {
    fprintf(out, "@0x%016jx - 0x%016jx: %s%s%s%s\n", it->first,
            std::next(it) == end ? -1 : std::next(it)->first - 1,
            it->second & DISASM_REGION_DATA ? "d" : "-",
            it->second & DISASM_REGION_CODE ? "c" : "-",
            it->second & DISASM_REGION_BB ? "b" : "-",
            it->second & DISASM_REGION_FUNC ? "f" : "-");
  }
}

unsigned
AddressMap::get_region_type(uint64_t addr) {
  auto it = std::prev(regions.upper_bound(addr));
  return it->second;
}

void
AddressMap::set_region_type(uint64_t addr, unsigned type) {
  auto it    = std::prev(regions.upper_bound(addr));
  it->second = type;
}

void
AddressMap::add_region_type(uint64_t addr, uint64_t size, unsigned type) {
  auto it = regions.upper_bound(addr);
  if (it != regions.end() && it->first < addr + size) {
    add_region_type(addr, it->first - addr, type);
    add_region_type(it->first, size - (it->first - addr), type);
  } else {
    auto types = std::prev(it)->second;
    if ((types & type) == type)
      return;

    if (it != regions.end() && it->second == types)
      regions.erase(it);
    it = regions.insert(it, std::make_pair(addr + size, types));

    if (std::prev(it)->first != addr)
      regions.insert(it, std::make_pair(addr, types | type));
    else if (std::prev(std::prev(it))->second == (std::prev(it)->second | type))
      regions.erase(std::prev(it));
    else
      std::prev(it)->second |= type;
  }
}

void
AddressMap::clr_region_type(uint64_t addr, uint64_t size, unsigned type) {
  auto it = regions.upper_bound(addr);
  if (it != regions.end() && it->first < addr + size) {
    clr_region_type(addr, it->first - addr, type);
    clr_region_type(it->first, size - (it->first - addr), type);
  } else {
    auto prev   = std::prev(it);
    auto types  = prev->second;
    auto ctypes = types & ~type;

    if (prev->first < addr) {
      if (it->second == ctypes)
        regions.erase(it);
      regions.insert(it, std::make_pair(addr, ctypes));
    } else if (std::prev(prev)->second == ctypes) {
      regions.erase(prev);
    } else {
      prev->second = ctypes;
    }

    if (it != regions.end() && it->first > addr + size) {
      regions.insert(it, std::make_pair(addr + size, types));
    }
  }
}

/*******************************************************************************
 **                            Disassembly engine                             **
 ******************************************************************************/
static int
init_disasm(Binary* bin, std::list<DisasmSection>* disasm) {
  size_t         i;
  uint64_t       vma;
  Section*       sec;
  DisasmSection* dis;

  disasm->clear();
  for (i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if ((sec->type != Section::SEC_TYPE_CODE) &&
        !(!options.only_code_sections && (sec->type == Section::SEC_TYPE_DATA)))
      continue;

    disasm->push_back(DisasmSection());
    dis = &disasm->back();

    dis->section = sec;
    dis->addrmap.add_region_type(sec->vma, sec->size,
                                 AddressMap::DISASM_REGION_CODE);
  }
  verbose(1, "disassembler initialized");

  return 0;
}

static int
fini_disasm(Binary* bin, std::list<DisasmSection>* disasm) {
  verbose(1, "disassembly complete");

  return 0;
}

static int
nucleus_disasm_bb(Binary* bin, DisasmSection* dis, BB* bb) {
  switch (bin->arch) {
  case Binary::ARCH_AARCH64:
    return nucleus_disasm_bb_aarch64(bin, dis, bb);
  case Binary::ARCH_ARM:
    return nucleus_disasm_bb_arm(bin, dis, bb);
  case Binary::ARCH_MIPS:
    return nucleus_disasm_bb_mips(bin, dis, bb);
  case Binary::ARCH_PPC:
    return nucleus_disasm_bb_ppc(bin, dis, bb);
  case Binary::ARCH_X86:
    return nucleus_disasm_bb_x86(bin, dis, bb);
  default:
    print_err("disassembly for architecture %s is not supported",
              bin->arch_str.c_str());
    return -1;
  }
}

static int
nucleus_disasm_section(Binary* bin, DisasmSection* dis) {
  int             ret;
  unsigned        i, n;
  uint64_t        vma;
  double          s;
  BB*             mutants;
  std::queue<BB*> Q;

  mutants = NULL;

  if ((dis->section->type != Section::SEC_TYPE_CODE) &&
      options.only_code_sections) {
    print_warn("skipping non-code section '%s'", dis->section->name.c_str());
    return 0;
  }

  verbose(2, "disassembling section '%s'", dis->section->name.c_str());

  Q.push(NULL);
  while (!Q.empty()) {
    n = bb_mutate(dis, Q.front(), &mutants);
    Q.pop();
    for (i = 0; i < n; i++) {
      if (nucleus_disasm_bb(bin, dis, &mutants[i]) < 0) {
        goto fail;
      }
      if ((s = bb_score(dis, &mutants[i])) < 0) {
        goto fail;
      }
    }
    if ((n = bb_select(dis, mutants, n)) < 0) {
      goto fail;
    }
    for (i = 0; i < n; i++) {
      if (mutants[i].alive) {
        dis->addrmap.add_region_type(
            mutants[i].start, mutants[i].end - mutants[i].start,
            AddressMap::DISASM_REGION_CODE | AddressMap::DISASM_REGION_BB);
        dis->BBs.push_back(BB(mutants[i]));
        Q.push(&dis->BBs.back());
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if (mutants) {
    delete[] mutants;
  }
  return ret;
}

int
nucleus_disasm(Binary* bin, std::list<DisasmSection>* disasm) {
  int ret;

  if (init_disasm(bin, disasm) < 0) {
    goto fail;
  }

  for (auto& dis : (*disasm)) {
    if (nucleus_disasm_section(bin, &dis) < 0) {
      goto fail;
    }
  }

  if (fini_disasm(bin, disasm) < 0) {
    goto fail;
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  return ret;
}
