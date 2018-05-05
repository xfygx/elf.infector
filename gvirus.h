------------------------------ gvirus.h ------------------------------

#ifndef _G2_PARASITE_CODE_

#define _G2_PARASITE_CODE_

#ifndef NDEBUG

#define PARACODE_RETADDR_ADDR_OFFSET 1704

#else

#define PARACODE_RETADDR_ADDR_OFFSET 1232

#endif

void parasite_code(void);

void parasite_code_end(void);

#endif

------------------------------ gvirus.h ------------------------------ 