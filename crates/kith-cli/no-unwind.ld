/* kith aborts on a panic and never unwinds: the tables that say how to (a seventh of the
   binary) are left out. The C start files keep theirs: they mark where the list begins. */
SECTIONS { /DISCARD/ : { *(EXCLUDE_FILE(*crtbegin*.o *crtend*.o) .eh_frame) } } INSERT BEFORE .eh_frame;
