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
uint32_t num_Key_Map = 0;
READ_KEY_MAP *Key_Map[KEYMAP_CNT];

uint32_t num_Subscriptions = 0;
SUBSCRIBE_KEY_MAP *S_Key_Map[S_KEYMAP_CNT];


/*------------------*/
/* BACnet - Handler */
/*------------------*/
void My_Read_Property_Ack_Handler(uint8_t *service_request,
                                  uint16_t service_len,
                                  BACNET_ADDRESS *src,
                                  BACNET_CONFIRMED_SERVICE_ACK_DATA *service_data)
{
    BACNET_READ_PROPERTY_DATA data;
    BACNET_APPLICATION_DATA_VALUE value;

    uint8_t  len = 0;
    uint8_t  application_data_len;
    uint8_t *application_data;

    DEBUG_MSG("--[ReadProp] ACK-Handler--");

    // Look for KeyMap containing InvokeID of received RP_ACK
    for (uint32_t i = 0; i < num_Key_Map; i++)
    {
        if (Key_Map[i]->invoke_ID == service_data->invoke_id)
        {
            len = rp_ack_decode_service_request(service_request, service_len, &data);

            if (len > 0)
            {
                application_data = data.application_data;
                application_data_len = data.application_data_len;

                len = bacapp_decode_application_data(application_data, application_data_len, &value);

                if (len > 0)
                {
                    switch (value.tag)
                    {
                    case BACNET_APPLICATION_TAG_ENUMERATED:
                        Key_Map[i]->data.Boolean = value.type.Boolean;
                        DEBUG_MSG("InvokeID (%u): %s", 
                                  service_data->invoke_id,
                                  (Key_Map[i]->data.Boolean == BINARY_ACTIVE) ? "TRUE" : "FALSE" );
                        break;

                    case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                        Key_Map[i]->data.Enumerated = value.type.Unsigned_Int;
                        DEBUG_MSG("InvokeID (%u): %u", service_data->invoke_id, Key_Map[i]->data.Enumerated);
                        break;

                    case BACNET_APPLICATION_TAG_REAL:
                        Key_Map[i]->data.Real = value.type.Real;
                        DEBUG_MSG("InvokeID (%u): %f", service_data->invoke_id, Key_Map[i]->data.Real);
                        break;
                    }
                }
            }

            // Free InvokeID and reset corresponding KeyMap
            tsm_free_invoke_id(Key_Map[i]->invoke_ID);
            Key_Map[i]->invoke_ID = 0;

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
    BACNET_PROPERTY_VALUE  property_value[2];
    BACNET_PROPERTY_VALUE *pProperty_value = NULL;
    uint32_t i = 0;

    DEBUG_MSG("--[CoVNotif] handler--");

    pProperty_value = &property_value[0];
    
    while (pProperty_value)
    {
        i++;

        if (i < 2) { pProperty_value->next = &property_value[i]; }
        else       { pProperty_value->next = NULL; }

        pProperty_value = pProperty_value->next;
    }

    cov_data.listOfValues = &property_value[0];
    uint32_t len = cov_notify_decode_service_request(service_request, service_len, &cov_data);

    if (len > 0)
    {
        for (i = 0; i < num_Subscriptions; i++)
        {
            if (S_Key_Map[i]->process_ID == cov_data.subscriberProcessIdentifier)
            {
                switch (cov_data.listOfValues->value.tag)
                {
                    case BACNET_APPLICATION_TAG_ENUMERATED:
                        S_Key_Map[i]->data.Boolean = cov_data.listOfValues->value.type.Boolean;
                        break;
    
                    case BACNET_APPLICATION_TAG_UNSIGNED_INT:
                        S_Key_Map[i]->data.Enumerated = cov_data.listOfValues->value.type.Unsigned_Int;
                        break;
                        
                    case BACNET_APPLICATION_TAG_REAL:
                        S_Key_Map[i]->data.Real = cov_data.listOfValues->value.type.Real;
                        break;
                }
                break;
            }
        }
    }

    return;
}

void MyWritePropertySimpleAckHandler(BACNET_ADDRESS *src, uint8_t invoke_id)
{
    // free InvokeID
    tsm_free_invoke_id(invoke_id);
    return;
}