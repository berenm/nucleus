#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "disasm.h"

bool
test(AddressMap addrmap) {
  addrmap.print_regions(stderr);
  auto begin = addrmap.regions.begin();
  REQUIRE(addrmap.regions.size() == 1);
  REQUIRE((begin)->first == 0);
  REQUIRE((begin++)->second == 0);

  puts("addrmap.insert(16, 16, 1);");
  addrmap.insert(16, 16, 1);
  addrmap.print_regions(stderr);
  begin = addrmap.regions.begin();
  REQUIRE(addrmap.regions.size() == 3);
  REQUIRE((begin)->first == 0);
  REQUIRE((begin++)->second == 0);
  REQUIRE((begin)->first == 16);
  REQUIRE((begin++)->second == 1);
  REQUIRE((begin)->first == 32);
  REQUIRE((begin++)->second == 0);

  fprintf(stderr, "addrmap.add_addr_flag(16, 32, 2);");
  addrmap.add_addr_flag(16, 32, 2);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.add_addr_flag(32, 16, 1);");
  addrmap.add_addr_flag(32, 16, 1);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.add_addr_flag(48, 16, 3);");
  addrmap.add_addr_flag(48, 16, 3);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.clr_addr_flag(24, 8, 1);");
  addrmap.clr_addr_flag(32, 16, 1);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.clr_addr_flag(24, 16, 2);");
  addrmap.clr_addr_flag(24, 16, 2);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.clr_addr_flag(32, 32, 1);");
  addrmap.clr_addr_flag(32, 32, 1);
  addrmap.print_regions(stderr);

  fprintf(stderr, "addrmap.clr_addr_flag(16, 48, 2);");
  addrmap.clr_addr_flag(16, 48, 2);
  addrmap.print_regions(stderr);

  return true;
}

TEST_CASE("AddressMap consistency", "[addrmap]") { test(AddressMap{}); }
