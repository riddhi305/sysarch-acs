/** 
 * B_SMMU_25: Check Secure Stage-2 via SMMUv3.2+ (EL3 read of S-bank).
 */

#include <stdint.h>
#include <stdbool.h>

#include "val/include/acs_val.h"
#include "val/include/acs_smmu.h"
#include "val/include/acs_iovirt.h"
#include "val/include/val_interface.h"
#include "val/include/acs_pe.h"

#define TEST_NUM   (ACS_SMMU_TEST_NUM_BASE + 23)
#define TEST_DESC  "Check Secure Stage-2 provided by SMMUv3.2+ (EL3 read of S-bank)"
#define TEST_RULE  "B_SMMU_25"

typedef enum {
  SMMU_REG_BANK_NS = 0,
  SMMU_REG_BANK_S  = 1
} smmu_reg_bank_e;

/* SCR_EL3.EEL2 bit (bit[18]) — enables Secure EL2 behavior */
#define SCR_EL3_EEL2   (1ULL << 18)

static
uint32_t 
smmu_aidr_minor(uint64_t aidr) { 
    return (uint32_t)(aidr & 0xF); 
}

static 
uint32_t 
smmu_idr0_s2p (uint64_t idr0) { 
    return (uint32_t)(idr0 & 0x1); 
}

static 
void 
payload(void)
{
  uint32_t pe_index = val_pe_get_index_mpid(val_pe_get_mpid());
  bool changed_eel2 = false;
  bool decided = false;

  /* 0) Require Secure EL2 implemented */
  {
    uint64_t pfr0 = val_pe_reg_read(ID_AA64PFR0_EL1);
    uint32_t s_el2 = VAL_EXTRACT_BITS(pfr0, 36, 39);
    val_print(ACS_PRINT_DEBUG, " S-EL2 implemented = %ld", s_el2);
    if (!s_el2) {
      val_print(ACS_PRINT_ERR, " Secure EL2 not implemented", 0);
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 1));
      decided = true;
      goto cleanup;
    }
  }

  /* 1) Ensure SCR_EL3.EEL2 = 1 so Secure EL2 behaviors are enabled */
  {
    uint64_t scr_old = 0;
    if (val_el3_get_scr(&scr_old) != 0) {
      val_print(ACS_PRINT_ERR, " EL3 GET_SCR_EL3 failed", 0);
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 2));
      decided = true;
      goto cleanup;
    }

    if ((scr_old & SCR_EL3_EEL2) == 0) {
      if (val_el3_update_scr(SCR_EL3_EEL2, 0) != 0) {
        val_print(ACS_PRINT_WARN, " Could not set SCR_EL3.EEL2=1; skipping SEL2-dependent check", 0);
        val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 3));
        decided = true;
        goto cleanup;
      }
      uint64_t scr_new = 0;
      if (val_el3_get_scr(&scr_new) != 0 || (scr_new & SCR_EL3_EEL2) == 0) {
        val_print(ACS_PRINT_WARN, " EEL2 did not take effect; skipping", 0);
        val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 4));
        decided = true;
        goto cleanup;
      }
      changed_eel2 = true;
    }
  }

  /* 2) Discover SMMU controllers */
  {
    uint32_t num_smmu = val_iovirt_get_smmu_info(SMMU_NUM_CTRL, 0);
    val_print(ACS_PRINT_DEBUG, " Num SMMU controllers = %ld", num_smmu);

    if (num_smmu == 0) {
      val_print(ACS_PRINT_ERR, " No SMMU controllers discovered", 0);
      val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 5));
      decided = true;
      goto cleanup;
    }

    /* 3) Check every controller */
    for (int32_t idx = (int32_t)num_smmu - 1; idx >= 0; --idx) {

      /* Must be v3.x and minor >= 2 (v3.2+) */
      uint32_t major = val_iovirt_get_smmu_info(SMMU_CTRL_ARCH_MAJOR_REV, idx);
      if (major < 3) {
        val_print(ACS_PRINT_ERR, " SMMU%ld: ", idx);
        val_print(ACS_PRINT_ERR, " Major rev %ld < 3", major);
        val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 1));
        decided = true;
        goto cleanup;
      }

      uint64_t aidr_ns = val_smmu_read_cfg(SMMUv3_AIDR, idx);
      uint32_t minor_ns = smmu_aidr_minor(aidr_ns);
      if (minor_ns < 2) {
        val_print(ACS_PRINT_ERR, " SMMU%ld: ", idx);
        val_print(ACS_PRINT_ERR, " Minor %ld < 2 (need v3.2+)", minor_ns);
        val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 2));
        decided = true;
        goto cleanup;
      }

      uint64_t idr0_ns = val_smmu_read_cfg(SMMUv3_IDR0, idx);
      if (!smmu_idr0_s2p(idr0_ns)) {
        val_print(ACS_PRINT_ERR, " SMMU%ld: NS bank reports no Stage-2", idx);
        val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 3));
        decided = true;
        goto cleanup;
      }

      /* Secure bank via EL3 (AIDR then IDR0) */
      uint64_t aidr_s = 0;
      {
        uint32_t rc = val_el3_smmu_read_bank((uint32_t)idx, SMMUv3_AIDR, SMMU_REG_BANK_S, &aidr_s);
        if (rc != 0) {
          val_print(ACS_PRINT_ERR, " EL3 SMMU AIDR read failed (idx %ld)", idx);
          val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 4));
          decided = true;
          goto cleanup;
        }
        val_print(ACS_PRINT_DEBUG, " S AIDR   : 0x%lx", aidr_s);

        if (aidr_s == 0ULL) {
          /* RAZ/WI suggests no Secure bank window mapped; cannot validate Secure bank → SKIP */
          val_print(ACS_PRINT_WARN, " SMMU%ld: Secure AIDR RAZ/WI (0) -> no Secure bank", idx);
          val_set_status(pe_index, RESULT_SKIP(TEST_NUM, 6));
          decided = true;
          goto cleanup;
        }

        uint32_t minor_s = smmu_aidr_minor(aidr_s);
        val_print(ACS_PRINT_DEBUG, " S minor  : %d", minor_s);
        if (minor_s < 2U) {
          val_print(ACS_PRINT_ERR, " SMMU%ld: ", idx);
          val_print(ACS_PRINT_ERR, " Secure bank v3.%u; need v3.2+", minor_s);
          val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 5));
          decided = true;
          goto cleanup;
        }
      }

      uint64_t idr0_s = 0;
      {
        uint32_t rc = val_el3_smmu_read_bank((uint32_t)idx, SMMUv3_IDR0, SMMU_REG_BANK_S, &idr0_s);
        if (rc != 0) {
          val_print(ACS_PRINT_ERR, " EL3 SMMU IDR0 read failed (idx %ld)", idx);
          val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 6));
          decided = true;
          goto cleanup;
        }
        val_print(ACS_PRINT_DEBUG, " S IDR0   : 0x%lx", idr0_s);

        if (!smmu_idr0_s2p(idr0_s)) {
          val_print(ACS_PRINT_ERR, " SMMU%ld: Secure bank present but Stage-2 not supported", idx);
          val_set_status(pe_index, RESULT_FAIL(TEST_NUM, 7));
          decided = true;
          goto cleanup;
        }
      }
    } /* for each SMMU */
  }

  if (!decided) {
    val_set_status(pe_index, RESULT_PASS(TEST_NUM, 1));
    decided = true;
  }

cleanup:
  /* Restoring SCR_EL3.EEL2 after enabling it */
  if (changed_eel2) {
    (void)val_el3_update_scr(0, SCR_EL3_EEL2);
  }
}

uint32_t 
s01_entry(uint32_t num_pe)
{
  uint32_t status = ACS_STATUS_FAIL;

  num_pe = 1;  // This test is run on single processor

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);
  if (status != ACS_STATUS_SKIP)
      val_run_test_payload(TEST_NUM, num_pe, payload, 0);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, ACS_END(TEST_NUM), NULL);
  return status; 
}
