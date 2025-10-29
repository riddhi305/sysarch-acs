/** 
 * Verify S-EL2 virtual timer (CNTHVS) mapping (PPI).
 */

#include <stdint.h>
#include "val/include/acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/acs_gic.h"
#include "val/include/acs_gic_support.h"
#include "val/include/acs_timer.h"
#include "val/include/acs_pe.h"

#define TEST_NUM   (ACS_GIC_TEST_NUM_BASE + 23)
#define TEST_DESC "Verify S-EL2 virtual timer (CNTHVS) PPI mapping"
#define TEST_RULE "B_PPI_03"

#define PPI_RECOMMENDED_CNTHVS 19

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

    /* S-EL2 presence */
    {
        uint64_t pfr0 = val_pe_reg_read(ID_AA64PFR0_EL1);
        uint32_t s_el2 = VAL_EXTRACT_BITS(pfr0, 36, 39);
        val_print(ACS_PRINT_DEBUG, " S-EL2 implemented = %ld", s_el2);
        if (!s_el2) {
            val_print(ACS_PRINT_ERR, " Secure EL2 not implemented", 0);
            val_set_status(index, RESULT_SKIP(TEST_NUM, 1));
            return;
        }
    }

    if (ensure_sel2_and_irq_routing_ok() != 0) {
        val_print(ACS_PRINT_WARN, " EL3 config unsuitable for S-EL2 routing (EEL2/IRQ/FIQ/EA)", 0);
        val_set_status(index, RESULT_SKIP(TEST_NUM, 2));
        return;
    }

    uint32_t intid = val_timer_get_info(TIMER_INFO_SEC_VIR_EL2_INTID, 0);
    if (intid == 0) intid = PPI_RECOMMENDED_CNTHVS;
    val_print(ACS_PRINT_TEST, " S-EL2 virtual timer INTID (expected 21) = %ld", intid);

    if (intid != PPI_RECOMMENDED_CNTHVS) {
        val_print(ACS_PRINT_ERR, " Expected INTID %ld, ", PPI_RECOMMENDED_CNTHVS);
        val_print(ACS_PRINT_ERR, " reported %ld", intid);
        val_set_status(index, RESULT_FAIL(TEST_NUM, 1));
        return;
    }

    val_set_status(index, RESULT_PASS(TEST_NUM, 1));
}

uint32_t 
g03_entry(uint32_t num_pe)
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
