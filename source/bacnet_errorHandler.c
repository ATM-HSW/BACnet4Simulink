/*----------*/
/* Includes */
/*----------*/

// Environmant
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// BACnet
#include "config.h"
#include "bactext.h"
#include "bacerror.h"
#include "iam.h"
#include "arf.h"
#include "tsm.h"
#include "address.h"
#include "npdu.h"
#include "device.h"
#include "net.h"
#include "datalink.h"
#include "whois.h"

#include "handlers.h"
#include "client.h"
#include "txbuf.h"

// Misc
#include "bacnet_myHandler.h"
#include "dbg_message.h"
#include "typedefs.h"


/*--------------------*/
/* External Variables */
/*--------------------*/


/*------------------*/
/* BACnet - Handler */
/*------------------*/

void MyErrorHandler(BACNET_ADDRESS *src,
                    uint8_t invoke_id,
                    BACNET_ERROR_CLASS error_class,
                    BACNET_ERROR_CODE error_code)
{
    DEBUG_MSG("--[ERROR]-handler--");

    //     if (address_match(&Target_Address, src) &&
    //         (invoke_id == Request_Invoke_ID)) {
    //         printf("BACnet Error: %s: %s\r\n",
    //             bactext_error_class_name((int) error_class),
    //             bactext_error_code_name((int) error_code));
    //         Error_Detected = true;
    //     }

    return;
}

void MyAbortHandler(BACNET_ADDRESS *src,
                    uint8_t invoke_id,
                    uint8_t abort_reason,
                    bool server)
{
    DEBUG_MSG("--[ABORT]-handler--");

    //     (void) server;
    //     if (address_match(&Target_Address, src) &&
    //         (invoke_id == Request_Invoke_ID)) {
    //         printf("BACnet Abort: %s\r\n",
    //             bactext_abort_reason_name((int) abort_reason));
    //         Error_Detected = true;
    //     }

    return;
}

void MyRejectHandler(BACNET_ADDRESS *src,
                    uint8_t invoke_id,
                    uint8_t reject_reason)
{
    DEBUG_MSG("--[REJECT]-handler--");

    //     if (address_match(&Target_Address, src) &&
    //         (invoke_id == Request_Invoke_ID)) {
    //         printf("BACnet Reject: %s\r\n",
    //             bactext_reject_reason_name((int) reject_reason));
    //         Error_Detected = true;
    //     }

    return;
}