/* ../kith-cli/no-unwind.ld, as lld takes it: kithd aborts on a panic and never unwinds, so
   the tables that say how to are left out (the C start files keep theirs: they mark where
   the list begins). lld has no INSERT for a discard, and a script is then all it knows of
   the layout: a section it does not name keeps its own name, one output section for every
   function. So the usual ones are named here, in the order lld lays them out by itself,
   after room for the file's own headers (the start code reads them from memory). Nor does
   lld, given a script, start a new page where what may be done with the memory changes: the
   last page of the code was then loaded a second time as data, which cannot be run.
   build.rs writes the functions kithd.order lists where that file is named below, first in
   the code and in its order. */
SECTIONS {
  . = SIZEOF_HEADERS;
  /DISCARD/ : { *(EXCLUDE_FILE(*crtbegin*.o *crtend*.o) .eh_frame) }
  .rodata : { *(.rodata .rodata.*) }
  .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) }
  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .text : {
    /* kithd.order */
    /* (Then the code written by hand, which has no section for each function: the C
       library's copying of memory is in it, and runs from the start.) */
    *(.text)
    *(.text .text.*)
  }
  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .tdata : { *(.tdata .tdata.*) }
  .tbss : { *(.tbss .tbss.*) }
  .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
  /* (What is written once at start and then read only ends here: lld puts the rest of it,
     which this does not name, before this line.) */
  . = ALIGN(CONSTANT(MAXPAGESIZE));
  .data : { *(.data .data.*) }
  .bss : { *(.bss .bss.*) }
}
