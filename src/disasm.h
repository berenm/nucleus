#ifndef NUCLEUS_DISASM_H
#define NUCLEUS_DISASM_H

#include <stdint.h>

#include <map>
#include <list>
#include <string>

#include <capstone/capstone.h>

#include "bb.h"
#include "dataregion.h"
#include "loader.h"

class AddressMap {
public:
  enum DisasmRegion {
    DISASM_REGION_UNMAPPED = 0x0000,
    DISASM_REGION_DATA     = 0x0001,
    DISASM_REGION_CODE     = 0x0002,
    DISASM_REGION_BB       = 0x0100,
    DISASM_REGION_FUNC     = 0x0200,
  };

  AddressMap() { regions[0] = DISASM_REGION_UNMAPPED; }

  void print_regions(FILE* out);

  unsigned get_region_type(uint64_t addr);
  void     set_region_type(uint64_t addr, unsigned type);
  void     add_region_type(uint64_t addr, uint64_t size, unsigned type);
  void     clr_region_type(uint64_t addr, uint64_t size, unsigned type);

private:
  std::map<uint64_t, unsigned> regions;
};

class DisasmSection {
public:
  DisasmSection() : section(NULL) {}

  void print_BBs(FILE* out);

  Section*              section;
  AddressMap            addrmap;
  std::list<BB>         BBs;
  std::list<DataRegion> data;

private:
  void sort_BBs();
};

int
nucleus_disasm(Binary* bin, std::list<DisasmSection>* disasm);

#endif /* NUCLEUS_DISASM_H */
