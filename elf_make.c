#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ELF Header (64-bit)
struct Elf64Header {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

// Program Header (64-bit)
struct Elf64ProgramHeader {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

static struct Elf64Header create_elf_header(void) {
    struct Elf64Header hdr;
    memset(&hdr, 0, sizeof(hdr));

    // e_ident
    hdr.e_ident[0] = 0x7F;     // ELF magic
    hdr.e_ident[1] = 'E';
    hdr.e_ident[2] = 'L';
    hdr.e_ident[3] = 'F';
    hdr.e_ident[4] = 2;        // 64-bit
    hdr.e_ident[5] = 1;        // little-endian
    hdr.e_ident[6] = 1;        // ELF version
    // rest of e_ident can remain zero

    hdr.e_type    = 2;         // ET_EXEC (executable)
    hdr.e_machine = 62;        // EM_X86_64
    hdr.e_version = 1;         // EV_CURRENT

    // We will place our code at virtual address 0x401000
    hdr.e_entry   = 0x401000;

    // Program header table right after the ELF header
    hdr.e_phoff   = sizeof(struct Elf64Header);

    // No section header table
    hdr.e_shoff   = 0;

    hdr.e_flags   = 0;
    hdr.e_ehsize  = sizeof(struct Elf64Header);
    hdr.e_phentsize = sizeof(struct Elf64ProgramHeader);
    hdr.e_phnum   = 1;         // We'll have one loadable segment
    hdr.e_shentsize = 0;
    hdr.e_shnum   = 0;
    hdr.e_shstrndx = 0;

    return hdr;
}

static struct Elf64ProgramHeader create_program_header(void) {
    struct Elf64ProgramHeader ph;
    memset(&ph, 0, sizeof(ph));

    ph.p_type   = 1;       // PT_LOAD (loadable segment)
    ph.p_flags  = 5;       // PF_R | PF_X  (read + execute)
    ph.p_offset = 0x1000;  // file offset where the segment begins
    ph.p_vaddr  = 0x401000;
    ph.p_paddr  = 0;       // not used
    ph.p_filesz = 0x100;   // size in file
    ph.p_memsz  = 0x100;   // size in memory
    ph.p_align  = 0x1000;  // page alignment

    return ph;
}

uint8_t code[] = {
    0xB8, 0x3C, 0x00, 0x00, 0x00,   // mov eax, 60
    0xB8, 0x3C, 0x00, 0x00, 0x00,   // mov eax, 60
    0xBF, 0x00, 0x00, 0x00, 0x00,   // mov edi, 0
    0x0F, 0x05                      // syscall
};

int main(void) {
    // Create the ELF header and program header
    struct Elf64Header         ehdr = create_elf_header();
    struct Elf64ProgramHeader  phdr = create_program_header();

    // Open output file
    FILE *fp = fopen("result", "wb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    // Write the ELF header
    fwrite(&ehdr, 1, sizeof(ehdr), fp);

    // Write the Program Header
    fwrite(&phdr, 1, sizeof(phdr), fp);

    // Pad until we reach offset 0x1000
    //    Current file offset = sizeof(ehdr) + sizeof(phdr) = 64 + 56 = 120 (0x78)
    //    We need to pad until 0x1000
    long current_offset = ftell(fp);
    if (current_offset < 0x1000) {
        // Fill with zeros up to 0x1000
        long padding_size = 0x1000 - current_offset;
        uint8_t *zeros = calloc(padding_size, 1);
        fwrite(zeros, 1, padding_size, fp);
        free(zeros);
    }

    // Write our machine code at offset 0x1000
    fwrite(code, 1, sizeof(code), fp);

    fclose(fp);

    printf("Created elf file result.\n");
    return 0;
}
