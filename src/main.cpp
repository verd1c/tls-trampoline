#include <iostream>
#include <pe.hpp>

int main() {
    PE pe( "./ConsoleApplication1.exe" );

    printf("Magic: %x\n", pe.dos_header.e_magic);
    printf("Offset to NT Header: %x\n", pe.dos_header.e_cblp);

    COFF_HEADER coff = pe.pe_header.coff_header;
    printf("Machine: %x\n", coff.machine);

    OptionalHeader oh = pe.pe_header.optional_header;
    printf("Magic: %x\n", oh.address_of_entry_point);
}