/*----------*/
/* Includes */
/*----------*/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "bacdef.h"
#include "config.h"
#include "bactext.h"
#include "bacerror.h"
#include "iam.h"
#include "arf.h"
#include "tsm.h"
#include "address.h"
#include "npdu.h"
#include "apdu.h"
#include "device.h"
#include "net.h"
#include "datalink.h"
#include "whois.h"

#include "handlers.h"
#include "client.h"
#include "txbuf.h"

#include "dbg_message.h"
#include "typedefs.h"


/*--------------------*/
/* External Variables */
/*--------------------*/
extern uint32_t num_Key_Map;
extern READ_KEY_MAP *Key_Map[255];

extern uint32_t num_Subscriptions;
extern SUBSCRIBE_KEY_MAP *S_Key_Map[255];


/*--------------------*/
/* BACnet - myHandler */
/*--------------------*/
static void MyErrorHandler(BACNET_ADDRESS *src,
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

void My_Read_Property_Ack_Handler(uint8_t *service_request,
                                  uint16_t service_len,
                                  BACNET_ADDRESS *src,
                                  BACNET_CONFIRMED_SERVICE_ACK_DATA *service_data)
{
    BACNET_READ_PROPERTY_DATA data;
    BACNET_APPLICATION_DATA_VALUE value;

    int len = 0;
    int application_data_len;
    uint8_t *application_data;


    DEBUG_MSG("--[ReadProp] ACK-Handler--");

    for (uint32_t ii = 0; ii < num_Key_Map; ii++)
    {
        if (Key_Map[ii]->invoke_ID = service_data->invoke_id)
        {
            len = rp_ack_decode_service_request(service_request, service_len, &data);
            if (len > 0)
            {
                application_data = data.application_data;
                application_data_len = data.application_data_len;

                len = bacapp_decode_application_data(application_data, (uint8_t)application_data_len, &value);

                if (len > 0)
                {
                    switch (value.tag)
                    {
                    case BACNET_APPLICATION_TAG_ENUMERATED:
                        Key_Map[ii]->data.Boolean = value.type.Boolean;
                        DEBUG_MSG(  "%d", Key_Map[ii]->data.Boolean);
                        break;
                    case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                        Key_Map[ii]->data.Enumerated = value.type.Unsigned_Int;
                        DEBUG_MSG(  "%d", Key_Map[ii]->data.Enumerated);
                        break;
                    case BACNET_APPLICATION_TAG_REAL:
                        Key_Map[ii]->data.Real = value.type.Real;
                        DEBUG_MSG(  "%f", Key_Map[ii]->data.Real);
                        break;
                    }
                }
            }

            tsm_invoke_id_free(Key_Map[ii]->invoke_ID);
            Key_Map[ii]->invoke_ID = 0;
            break;
        }
    }

    return;
}

void My_Unconfirmed_COV_Notification_Handler(uint8_t *service_request,
                                             uint16_t service_len,
                                             BACNET_ADDRESS *src)
{
    BACNET_COV_DATA cov_data;
    BACNET_PROPERTY_VALUE property_value[2];
    BACNET_PROPERTY_VALUE *pProperty_value = NULL;
    uint32_t ii = 0;

    DEBUG_MSG("--[UcofNotif] handler--");

    pProperty_value = &property_value[0];
    
    while (pProperty_value)
    {
        ii++;

        if (ii < 2) { pProperty_value->next = &property_value[ii]; }
        else        { pProperty_value->next = NULL; }

        pProperty_value = pProperty_value->next;
    }

    cov_data.listOfValues = &property_value[0];
    uint32_t len = cov_notify_decode_service_request(service_request, service_len, &cov_data);

    if (len > 0)
    {
        for (ii = 0; ii < num_Subscriptions; ii++)
        {
            if (S_Key_Map[ii]->process_ID == cov_data.subscriberProcessIdentifier)
            {
                switch (cov_data.listOfValues->value.tag)
                {
                case BACNET_APPLICATION_TAG_ENUMERATED:
                    S_Key_Map[ii]->data.Boolean = cov_data.listOfValues->value.type.Boolean;
                    break;
                case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                    S_Key_Map[ii]->data.Enumerated = cov_data.listOfValues->value.type.Unsigned_Int;
                    break;
                case BACNET_APPLICATION_TAG_REAL:
                    S_Key_Map[ii]->data.Real = cov_data.listOfValues->value.type.Real;
                    break;
                }
                break;
            }
        }
    }

    return;
}

void MyWritePropertySimpleAckHandler(BACNET_ADDRESS *src,
                                     uint8_t invoke_id)
{
    tsm_invoke_id_free(invoke_id);
    return;
}

static void Init_Service_Handlers(void)
{
    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_bind);

    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler(handler_unrecognized_service);

    /* we must implement read property - it's required! */
    //apdu_set_confirmed_handler(SERVICE_CONFIRMED_READ_PROPERTY,
    //    handler_read_property);
    /* handle the data coming back from confirmed requests */
    apdu_set_confirmed_ack_handler(SERVICE_CONFIRMED_READ_PROPERTY,
                                   My_Read_Property_Ack_Handler);

    /* handle the ack coming back */
    apdu_set_confirmed_simple_ack_handler(SERVICE_CONFIRMED_WRITE_PROPERTY,
                                          MyWritePropertySimpleAckHandler);

    /* handle the Simple ack coming back from SubscribeCOV */
    apdu_set_confirmed_simple_ack_handler(SERVICE_CONFIRMED_SUBSCRIBE_COV,
                                          MyWritePropertySimpleAckHandler);

    /* handle the data coming back from COV subscriptions */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_COV_NOTIFICATION,
                                 My_Unconfirmed_COV_Notification_Handler);

    /* handle any errors coming back */
    apdu_set_error_handler(SERVICE_CONFIRMED_READ_PROPERTY, MyErrorHandler);
    apdu_set_error_handler(SERVICE_CONFIRMED_SUBSCRIBE_COV, MyErrorHandler);
    apdu_set_error_handler(SERVICE_CONFIRMED_WRITE_PROPERTY, MyErrorHandler);
    apdu_set_abort_handler(MyAbortHandler);
    apdu_set_reject_handler(MyRejectHandler);

    return;
}