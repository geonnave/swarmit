#ifndef __NVMC_H
#define __NVMC_H

#include <stdlib.h>
#include <stdint.h>

//=========================== defines ==========================================

#define FLASH_PAGE_SIZE 4096
#define FLASH_OFFSET 0x0

//=========================== public ===========================================

/// Erase and write pages of the NON-SECURE region (the user image at 0x10000
/// and above). These drive NVMC through CONFIGNS.
void nvmc_page_erase(uint32_t page);
void nvmc_write(const uint32_t *addr, const void *input, size_t len);

/// Erase and write pages of the SECURE region (below 0x10000, which
/// tz_configure_flash_secure(0, 4) covers). Secure code reaches secure flash
/// only through CONFIG; CONFIGNS applies to the non-secure region alone
/// (nRF5340 PS v1.6 section 7.21.1), so the pair above cannot write here.
void nvmc_page_erase_secure(uint32_t page);
void nvmc_write_secure(const uint32_t *addr, const void *input, size_t len);

#endif
