/**
 * B_TIME_03 / TIME_03 — System counter must not roll over within 10 years.
 *
 *   Let f = CNTFRQ_EL0 (Hz).
 *   If (Armv8.4+ && Counter Scaling (CNTSC) implemented) → width N = 64 by rule.
 *     ⇒ PASS if f ≤ fmax(64); else FAIL.
 *   Else (no scaling or < v8.4) → N ≥ 56 by rule, but actual N may be >56.
 *     ⇒ If f ≤ fmax(56) → PASS (even min width suffices).
 *     ⇒ If f > fmax(64) → FAIL (even 64 wouldn't last 10 years).
 *     ⇒ Otherwise (fmax(56) < f ≤ fmax(64)) → Ambiguous
 *          (actual N unknown architecturally) → SKIP/UNDETERMINED with reason.
 */

#include <stdbool.h>
#include <stdint.h>
#include "val/include/acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/acs_timer.h"
#include "val/include/acs_pe.h"

#define TEST_NUM    (ACS_TIMER_TEST_NUM_BASE + 12)
#define TEST_DESC   "System counter must not roll over within 10 years"
#define TEST_RULE   "B_TIME_03"

/* 10 years ≈ 365.25 days */
#define TEN_YEARS_S          (315576000ULL)
#define ARCH_V8_4_CODE       (0x84)


/* ID_AA64MMFR2_EL1.TTL[51:48] non-zero ⇒ Armv8.4+ */
static 
bool 
is_arch_v8_4_plus(void)
{
    uint64_t mmfr2 = val_pe_reg_read(ID_AA64MMFR2_EL1);
    uint64_t ttl   = (mmfr2 >> 48) & 0xF;
    val_print(ACS_PRINT_DEBUG, " ID_AA64MMFR2_EL1 = 0x%lx, ", mmfr2);
    val_print(ACS_PRINT_DEBUG, "  TTL[51:48]=0x%lx\n", ttl);
    return ttl != 0;
}

static 
bool 
discover_cntsc_via_cntid(void)
{
    uint32_t n = val_timer_get_info(TIMER_INFO_NUM_PLATFORM_TIMERS, 0);
    bool saw_access = false;

    for (uint32_t i = 0; i < n; ++i) {
        uint64_t cntctl = val_timer_get_info(TIMER_INFO_SYS_CNTL_BASE, i);
        if (cntctl == 0) {
            val_print(ACS_PRINT_DEBUG, " CNTCTL base missing for frame %ld — skip\n", i);
            continue;
        }
        uint32_t cntid = 0;
        int rc = val_el3_read_cntid(cntctl, &cntid);
        if (rc != 0) {
            val_print(ACS_PRINT_DEBUG, " CNTID read failed at frame %ld ", i);
            val_print(ACS_PRINT_DEBUG, " (rc=%ld)\n", rc);
            continue;
        }
        saw_access = true;
        val_print(ACS_PRINT_DEBUG, " CNTID(frame %ld) = ", i);
        val_print(ACS_PRINT_DEBUG, " 0x%lx\n", cntid);

        uint32_t cntsc = cntid & 0xF;
        if (cntsc == 1) return true;   /* scaling implemented */
        if (cntsc == 0) continue;      /* not implemented at this frame */
    }

    if (!saw_access) {
        val_print(ACS_PRINT_WARN,
            " No readable CNTID frames via EL3 — treating scaling as NOT implemented\n", 0);
    }
    return false; 
}

static 
uint64_t 
fmax_for_10y(uint32_t width_bits)
{
    if (width_bits >= 64u) {
        return (UINT64_MAX / TEN_YEARS_S); 
    }
    uint64_t ticks = (1ULL << width_bits);
    return (ticks / TEN_YEARS_S);
}

static
void 
payload(void)
{
    uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
    val_print(ACS_PRINT_WARN, " PE index: %ld\n", pe_index);

    {
        uint64_t pfr0 = val_pe_reg_read(ID_AA64PFR0_EL1);
        uint64_t el1_a64 = (pfr0 >> 4) & 0xF;
        val_print(ACS_PRINT_DEBUG, " ID_AA64PFR0_EL1 = 0x%lx, ", pfr0);
        val_print(ACS_PRINT_DEBUG, " EL1.AArch64=%ld\n", el1_a64);
        if (el1_a64 == 0) {
            val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 1));
            return;
        }
    }

    /* 1. Read frequency f = CNTFRQ_EL0 (Hz) */
    uint64_t f_hz = val_timer_get_info(TIMER_INFO_CNTFREQ, 0);
    val_print(ACS_PRINT_DEBUG, " CNTFRQ_EL0 (Hz) = %ld\n", f_hz);
    if (f_hz == 0) {
        val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 1));
        return;
    }

    /* 2. Determine (v8.4+ ?) and whether FEAT_CNTSC is implemented */
    bool v84  = is_arch_v8_4_plus();
    bool cntsc = discover_cntsc_via_cntid();   /* true if any frame reports CNTSC=1 */

    /* 3. Compute 10-year safe frequency caps for 56 and 64 bits */
    const uint64_t fmax56 = fmax_for_10y(56);
    const uint64_t fmax64 = fmax_for_10y(64);

    val_print(ACS_PRINT_DEBUG, " 10y fmax: 56b=%ld Hz, ", fmax56);
    val_print(ACS_PRINT_DEBUG, "  64b=%ld Hz\n", fmax64);
    val_print(ACS_PRINT_DEBUG, " v8.4+ = %ld, ", v84);
    val_print(ACS_PRINT_DEBUG, "  CNTSC(scaling) = %ld\n", cntsc);

    if (v84 && cntsc) {
        if (f_hz <= fmax64) {
            val_set_status(pe_index, RESULT_PASS(TEST_NUM, 1));
            return;
        } else {
            val_print(ACS_PRINT_ERR,
                " FAIL: v8.4+ with scaling ⇒ N=64, but CNTFRQ(%ld) ", f_hz);
            val_print(ACS_PRINT_ERR,
                "  > 10y fmax64(%ld)\n", fmax64);
            val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 2));
            return;
        }
    } else {
        if (f_hz <= fmax56) {
            val_set_status(pe_index, RESULT_PASS(TEST_NUM, 2));
            return;
        } else if (f_hz > fmax64) {
            val_print(ACS_PRINT_ERR,
                " FAIL: CNTFRQ(%ld) ", f_hz);
            val_print(ACS_PRINT_ERR,
                "  > 10y fmax64(%ld) — cannot meet 10y with any N≤64\n", fmax64);
            val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 3));
            return;
        } else {
            val_print(ACS_PRINT_WARN,
                " UNDETERMINED: CNTFRQ(%ld) ", f_hz);
            val_print(ACS_PRINT_WARN,
                "  in (fmax56=%ld, ", fmax56);
            val_print(ACS_PRINT_WARN,
                "  fmax64=%ld]. Platform doesn't mandate 64-bit width and actual N is not discoverable.\n", fmax64);
            val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 2));
            return;
        }
    }
}

uint32_t 
t02_entry(uint32_t num_pe)
{
    uint32_t status = ACS_STATUS_FAIL;

    num_pe = 1;  /* Single-PE test */

    status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);
    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(TEST_NUM, num_pe, payload, 0);

    status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);
    val_report_status(0, ACS_END(TEST_NUM), NULL);
    return status;
}
