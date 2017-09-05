cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(nucleus CXX)

add_subdirectory(capstone-next EXCLUDE_FROM_ALL)

add_library(nucleus-lib
  src/bb.cc
  src/bb.h
  src/cfg.cc
  src/cfg.h
  src/dataregion.cc
  src/dataregion.h
  src/disasm-aarch64.cc
  src/disasm-aarch64.h
  src/disasm-arm.cc
  src/disasm-arm.h
  src/disasm.cc
  src/disasm.h
  src/disasm-mips.cc
  src/disasm-mips.h
  src/disasm-ppc.cc
  src/disasm-ppc.h
  src/disasm-x86.cc
  src/disasm-x86.h
  src/edge.cc
  src/edge.h
  src/exception.cc
  src/exception.h
  src/export.cc
  src/export.h
  src/function.cc
  src/function.h
  src/insn.cc
  src/insn.h
  src/loader.cc
  src/loader.h
  src/log.cc
  src/log.h
  src/nucleus.cc
  src/nucleus.h
  src/options.cc
  src/options.h
  src/strategy.cc
  src/strategy.h
  src/util.cc
  src/util.h
)
target_include_directories(nucleus-lib PUBLIC "src" "include" "capstone-next/include")
target_link_libraries(nucleus-lib PUBLIC capstone-static bfd)

add_executable(nucleus
  src/nucleus.cc
  src/nucleus.h
)
target_link_libraries(nucleus PUBLIC nucleus-lib)
