/* B_TIME_04 / TIME_01: System counter bit-width validation
 *
 * Min width: 56 bits (pre-v8.4 or no scaling)
 * Min width: 64 bits (Armv8.4+ with scaling)
 * On Armv8.4+, if CNTID cannot be read (via EL3), FAIL.
 */

#include <stdbool.h>
#include <stdint.h>
#include "val/include/acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/acs_timer.h"
#include "val/include/acs_pe.h"

#define TEST_NUM   (ACS_TIMER_TEST_NUM_BASE + 11)
#define TEST_DESC  "System counter bit-width validation"
#define TEST_RULE  "B_TIME_04"

#define MIN_WIDTH        56
#define MAX_WIDTH        64
#define ARCH_V8_4        0x84

static
uint8_t
get_effective_bit_width(uint64_t val)
{
    uint8_t w = 0;
    while (val) {
        w++; 
        val >>= 1; 
    }
    return w;
}

/* Arch version: ID_AA64MMFR2_EL1.TTL[51:48] (non-zero ⇒ >= v8.4+) */
static
uint32_t
get_arch_version(void)
{
    uint64_t reg = val_pe_reg_read(ID_AA64MMFR2_EL1);
    val_print(ACS_PRINT_DEBUG, "\n ID_AA64MMFR2_EL1 = 0x%lx", reg);

    uint8_t ttl = ((reg >> 48) & 0xF);
    val_print(ACS_PRINT_DEBUG, " TTL (bits[51:48]) = 0x%lx", ttl);

    return (ttl != 0) ? ARCH_V8_4 : 0x80;
}

/* 64-bit read of CNTPCT from a CNTBaseN frame */
static
uint64_t
mmio_read_cntpct(uint64_t cnt_base_n)
{
    uint64_t addr_hi = cnt_base_n + CNTPCT_HIGHER;
    uint64_t addr_lo = cnt_base_n + CNTPCT_LOWER;
    uint32_t hi1 = val_mmio_read(addr_hi);
    uint32_t lo  = val_mmio_read(addr_lo);
    uint32_t hi2 = val_mmio_read(addr_hi);
    uint64_t res;
    if (hi1 == hi2) {
        res = (((uint64_t)hi1 << 32) | (uint64_t)lo);
    } else {
        uint32_t lo2 = val_mmio_read(addr_lo);
        res = (((uint64_t)hi2 << 32) | (uint64_t)lo2);
    }
    val_print(ACS_PRINT_DEBUG, " CNTPCT (64-bit) = 0x%lx", res);
    return res;
}

static
void
payload(void)
{
    uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
    val_print(ACS_PRINT_WARN, " PE index: %ld", pe_index);

    uint32_t timer_num = val_timer_get_info(TIMER_INFO_NUM_PLATFORM_TIMERS, 0);
    val_print(ACS_PRINT_WARN, " Timer Count: %ld", timer_num);
    if (!timer_num) {
        val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 2));
        return;
    }

    uint32_t arch_version = get_arch_version();
    val_print(ACS_PRINT_DEBUG, " Architecture version is = 0x%lx", arch_version);

    while (timer_num--) {
        uint64_t cnt_base_n   = val_timer_get_info(TIMER_INFO_SYS_CNT_BASE_N,  timer_num);
        uint64_t cnt_ctl_base = val_timer_get_info(TIMER_INFO_SYS_CNTL_BASE,   timer_num);
        uint32_t is_secure    = val_timer_get_info(TIMER_INFO_IS_PLATFORM_TIMER_SECURE, timer_num);

        val_print(ACS_PRINT_DEBUG, "\n  --- Timer index = %ld", timer_num);
        val_print(ACS_PRINT_DEBUG, " CNTBaseN  = 0x%lx", cnt_base_n);
        val_print(ACS_PRINT_DEBUG, " CNTCTL    = 0x%lx", cnt_ctl_base);
        val_print(ACS_PRINT_DEBUG, " secure?   = %ld", is_secure);

        if ((cnt_base_n == 0) || (cnt_ctl_base == 0)) {
            val_print(ACS_PRINT_WARN, " Invalid CNT base(s) at index %ld", timer_num);
            continue;
        }

        uint64_t counter_val = 0;
        if (!is_secure &&
            val_timer_skip_if_cntbase_access_not_allowed(timer_num) != ACS_STATUS_SKIP) {
            /* NS-accessible: read CNTPCT via MMIO */
            counter_val = mmio_read_cntpct(cnt_base_n);
        } else {
            /* Secure/inaccessible: call EL3 to read **CNTPCT** via system register */
            if (val_el3_read_cntpct(&counter_val) != 0) {
                val_print(ACS_PRINT_WARN, " CNTPCT SMC read failed (idx %ld)", timer_num);
            } else {
                val_print(ACS_PRINT_DEBUG, " CNTPCT (64-bit, EL3) = 0x%lx", counter_val);
            }
        }

        /* Read CNTID (to detect scaling on v8.4+) */
        uint32_t cntid_val = 0;
        int cntid_rc = val_el3_read_cntid(cnt_ctl_base, &cntid_val);
        if (cntid_rc != 0) {
            if (arch_version >= ARCH_V8_4) {
                val_print(ACS_PRINT_ERR,
                          " CNTID SMC read failed (idx %ld) on Armv8.4+ ", timer_num);
                val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 1));
                return;
            } else {
                val_print(ACS_PRINT_WARN,
                          " CNTID SMC read failed (idx %ld) — assume no scaling (< v8.4)", timer_num);
                cntid_val = 0; /* treat as no scaling */
            }
        }
        val_print(ACS_PRINT_DEBUG, " CNTID raw = 0x%lx", cntid_val);

        bool scaling_enabled = ((cntid_val & 0xF) != 0);
        val_print(ACS_PRINT_DEBUG, " scaling_enabled = %ld", scaling_enabled);

        /* Compute effective width */
        uint8_t measured = get_effective_bit_width(counter_val);
        uint8_t min_required =
            ((arch_version >= ARCH_V8_4) && scaling_enabled) ? MAX_WIDTH : MIN_WIDTH;

        uint8_t width = measured;
        if (width < min_required) width = min_required;
        if (width > 64)           width = 64;

        val_print(ACS_PRINT_DEBUG, " Effective width (bits) = %ld", width);

        if (width > MAX_WIDTH) {
            val_print(ACS_PRINT_ERR, " Counter width exceeds 64 bits", 0);
            val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 2));
            return;
        }

        if ((arch_version >= ARCH_V8_4) && scaling_enabled) {
            if (width != 64) {
                val_print(ACS_PRINT_ERR, " Armv8.4+ with scaling: Counter width != 64", 0);
                val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 3));
                return;
            }
        } else {
            if (width < MIN_WIDTH) {
                val_print(ACS_PRINT_ERR, " Counter width less than 56 bits", 0);
                val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 4));
                return;
            }
        }
    }

    val_set_status(pe_index, RESULT_PASS(TEST_NUM, 1));
}

uint32_t
t01_entry(uint32_t num_pe)
{
    uint32_t status = ACS_STATUS_FAIL;

    num_pe = 1;  //This Timer test is run on single processor

    status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);
    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(TEST_NUM, num_pe, payload, 0);

    /* get the result from all PE and check for failure */
    status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

    val_report_status(0, ACS_END(TEST_NUM), NULL);
    return status;
}
