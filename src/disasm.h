#ifndef NUCLEUS_DISASM_H
#define NUCLEUS_DISASM_H

#include <stdint.h>

#include <map>
#include <unordered_map>
#include <list>
#include <string>

#include <capstone/capstone.h>

#include "bb.h"
#include "loader.h"

class AddressMap {
public:
  enum DisasmRegion {
    DISASM_REGION_UNMAPPED = 0x00,
    DISASM_REGION_DATA     = 0x01,
    DISASM_REGION_CODE     = 0x02,
    DISASM_REGION_BB       = 0x04,
    DISASM_REGION_FUNC     = 0x08,

    ADDRESS_FLAG_NONE     = 0x00,
    ADDRESS_FLAG_START_BB = 0x01,
    ADDRESS_FLAG_START_FN = 0x02,
  };

  AddressMap() { regions[0] = DISASM_REGION_UNMAPPED; }

  void print_regions(FILE* out);

  uint8_t get_region_type(uint64_t addr);
  void    set_region_type(uint64_t addr, uint8_t type);
  void    add_region_type(uint64_t addr, uint64_t size, uint8_t type);
  void    clr_region_type(uint64_t addr, uint64_t size, uint8_t type);

  uint8_t get_address_flag(uint64_t addr) {
    auto it = flags.find(addr);
    if (it != flags.end())
      return it->second;
    return ADDRESS_FLAG_NONE;
  }
  void add_address_flag(uint64_t addr, uint8_t flag) { flags[addr] |= flag; }
  void clr_address_flag(uint64_t addr, uint8_t flag) { flags[addr] &= ~flag; }

private:
  std::map<uint64_t, uint8_t> regions;
  std::map<uint64_t, uint8_t> flags;
};

class DisasmSection {
public:
  DisasmSection() : section(NULL) {}

  void print_BBs(FILE* out);

  Section*      section;
  AddressMap    addrmap;
  std::list<BB> BBs;

private:
  void sort_BBs();
};

int
nucleus_disasm(Binary* bin, std::list<DisasmSection>* disasm);

#endif /* NUCLEUS_DISASM_H */
