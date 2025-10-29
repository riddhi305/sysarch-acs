/**
 * Verify S-EL2 physical timer (CNTHPS) mapping (PPI/EPPI)
 */

#include <stdint.h>
#include "val/include/acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/acs_gic.h"
#include "val/include/acs_gic_support.h"
#include "val/include/acs_timer.h"
#include "val/include/acs_pe.h"

#define TEST_NUM   (ACS_GIC_TEST_NUM_BASE + 22)
#define TEST_DESC  "Verify S-EL2 physical timer (CNTHPS) PPI mapping"
#define TEST_RULE  "B_PPI_03"

#define PPI_RECOMMENDED_CNTHPS  (20)

static
int
ensure_sel2_and_irq_routing_ok(void)
{
    const uint64_t BIT_EEL2 = (1ull << 18);
    const uint64_t BIT_IRQ  = (1ull << 1);
    const uint64_t BIT_FIQ  = (1ull << 2);
    const uint64_t BIT_EA   = (1ull << 3);

    uint64_t scr = 0;
    if (val_el3_get_scr(&scr) != 0) return -1;

    uint64_t set_bits   = 0;
    uint64_t clear_bits = 0;

    if ((scr & BIT_EEL2) == 0) set_bits   |= BIT_EEL2;
    if (scr & BIT_IRQ)         clear_bits |= BIT_IRQ;
    if (scr & BIT_FIQ)         clear_bits |= BIT_FIQ;
    if (scr & BIT_EA)          clear_bits |= BIT_EA;

    if (set_bits || clear_bits) {
        if (val_el3_update_scr(set_bits, clear_bits) != 0) return -1;
        if (val_el3_get_scr(&scr) != 0) return -1;
        if ((scr & BIT_EEL2) == 0) return -1;
        if (scr & (BIT_IRQ | BIT_FIQ | BIT_EA)) return -1;
    }
    return 0;
}

static
void
payload(void)
{
    uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());

    /* Check S-EL2 presence */
    {
        uint64_t pfr0 = val_pe_reg_read(ID_AA64PFR0_EL1);
        uint32_t s_el2 = VAL_EXTRACT_BITS(pfr0, 36, 39);
        val_print(ACS_PRINT_DEBUG, " S-EL2 implemented = %ld", (uint64_t)s_el2);
        if (!s_el2) {
            val_print(ACS_PRINT_ERR, " Secure EL2 not implemented", 0);
            val_set_status(index, RESULT_SKIP(TEST_NUM, 1));
            return;
        }
    }

    /* Ensures EL3 configuration allows S-EL2 routing (EEL2=1, IRQ/FIQ/EA not routed to EL3). */
    if (ensure_sel2_and_irq_routing_ok() != 0) {
        val_print(ACS_PRINT_WARN, " EL3 config unsuitable for S-EL2 routing (EEL2/IRQ/FIQ/EA)", 0);
        val_set_status(index, RESULT_SKIP(TEST_NUM, 2));
        return;
    }

    uint32_t intid = val_timer_get_info(TIMER_INFO_SEC_PHY_EL2_INTID, 0);
    val_print(ACS_PRINT_DEBUG, " CNTHPS INTID (reported) = %ld", (uint64_t)intid);

    if (intid == 0) {
        val_print(ACS_PRINT_ERR, " CNTHPS INTID reported as 0", 0);
        val_set_status(index, RESULT_FAIL(TEST_NUM, 1));
        return;
    }

    /* Must be a PPI (16..31) or a valid EPPI */
    if ((intid < 16U || intid > 31U) && !val_gic_is_valid_eppi(intid)) {
        val_print(ACS_PRINT_ERR, " CNTHPS INTID not a valid PPI/EPPI: %ld", (uint64_t)intid);
        val_set_status(index, RESULT_FAIL(TEST_NUM, 2));
        return;
    }

    val_print(ACS_PRINT_TEST,
              " S-EL2 physical timer (CNTHPS) INTID (expected 20) = %ld",
              (uint64_t)intid);

    if (intid != PPI_RECOMMENDED_CNTHPS) {
        val_print(ACS_PRINT_ERR, " Expected INTID %ld, ", PPI_RECOMMENDED_CNTHPS);
        val_print(ACS_PRINT_ERR, " reported %ld", (uint64_t)intid);
        val_set_status(index, RESULT_FAIL(TEST_NUM, 3));
        return;
    }

    val_set_status(index, RESULT_PASS(TEST_NUM, 1));
}

uint32_t
g02_entry(uint32_t num_pe)
{
    uint32_t status = ACS_STATUS_FAIL;

    /* This PPI test runs on a single processor */
    num_pe = 1;

    status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);
    if (status != ACS_STATUS_SKIP)
        val_run_test_payload(TEST_NUM, num_pe, payload, 0);

    /* Collect results */
    status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

    val_report_status(0, ACS_END(TEST_NUM), NULL);
    return status;
}
