/** 
 * Verify Secure Physical timer (CNTPS) mapping; optionally poke at EL3 only.
 */

#include <stdint.h>
#include "val/include/acs_val.h"
#include "val/include/val_interface.h"
#include "val/include/acs_timer.h"
#include "val/include/acs_pe.h"
#include "val/include/acs_gic.h"
#include "val/include/pal_interface.h"

#define TEST_NUM  (ACS_GIC_TEST_NUM_BASE + 21)
#define TEST_DESC "Verify Secure Physical timer (CNTPS) mapping"
#define TEST_RULE "B_PPI_03"

static 
void 
payload(void)
{
    uint32_t idx = val_pe_get_index_mpid(val_pe_get_mpid());

    uint32_t intid = val_timer_get_info(TIMER_INFO_SEC_PHY_EL1_INTID, 0);
    val_print(ACS_PRINT_DEBUG, " CNTPS PPI INTID (reported) = %ld", intid);

    /* Checking whether it is PPI/EPPI or not */
    if ((intid < 16 || intid > 31) && !val_gic_is_valid_eppi(intid)) {
        val_print(ACS_PRINT_ERR, " CNTPS INTID not a valid PPI/EPPI: %ld", intid);
        val_set_status(idx, RESULT_FAIL(TEST_NUM, 1));
        return;
    }

    /* program and then immediately disable at EL3. No NS ISR. */
    uint64_t freq  = val_timer_get_info(TIMER_INFO_CNTFREQ, 0);
    uint64_t ticks = (freq / 1000U); 

    if (ticks == 0){
        ticks = 1;
    }

    val_el3_cntps_program(ticks);
    val_el3_cntps_disable();

    val_set_status(idx, RESULT_PASS(TEST_NUM, 1));
}

uint32_t 
g01_entry(uint32_t num_pe)
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
