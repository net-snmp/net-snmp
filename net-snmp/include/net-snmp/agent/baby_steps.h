/*
 * $Id$
 */
#ifndef BABY_STEPS_H
#define BABY_STEPS_H

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * The helper expands the original net-snmp set modes into the newer, finer
 * grained set modes.
 */

netsnmp_mib_handler *netsnmp_get_baby_steps_handler(u_long modes);
void            netsnmp_init_baby_steps_helper(void);

Netsnmp_Node_Handler netsnmp_baby_steps_helper;

    /*
     * Flags for baby step modes
     */
#define BABY_STEP_NONE                  0
#define BABY_STEP_PRE_REQUEST           (0x1 <<  1)
#define BABY_STEP_OBJECT_LOOKUP         (0x1 <<  2)
#define BABY_STEP_CHECK_OBJECT          (0x1 <<  3)
#define BABY_STEP_ROW_CREATE            (0x1 <<  4)
#define BABY_STEP_UNDO_SETUP            (0x1 <<  5)
#define BABY_STEP_SET_VALUES            (0x1 <<  6)
#define BABY_STEP_CHECK_CONSISTENCY     (0x1 <<  7)
#define BABY_STEP_UNDO_SETS             (0x1 <<  8)
#define BABY_STEP_COMMIT                (0x1 <<  9)
#define BABY_STEP_UNDO_COMMIT           (0x1 << 10)
#define BABY_STEP_IRREVERSIBLE_COMMIT   (0x1 << 11)
#define BABY_STEP_UNDO_CLEANUP          (0x1 << 12)
#define BABY_STEP_POST_REQUEST          (0x1 << 13)

#define BABY_STEP_ALL                   (0xffffffff)

#ifdef __cplusplus
}
#endif
#endif /* baby_steps */
