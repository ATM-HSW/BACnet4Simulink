#ifndef _BACNET_MY_HANDLER_H_
#define _BACNET_MY_HANDLER_H_

/*----------*/
/* Includes */
/*----------*/
#include "bacdef.h"
#include "apdu.h"


/*------------*/
/* Prototypes */
/*------------*/

// MyHandlers
void MyWritePropertySimpleAckHandler(BACNET_ADDRESS *src, uint8_t invoke_id);

void My_Unconfirmed_COV_Notification_Handler(uint8_t *service_request,
                                             uint16_t service_len,
                                             BACNET_ADDRESS *src);

void My_Read_Property_Ack_Handler(uint8_t *service_request,
                                  uint16_t service_len,
                                  BACNET_ADDRESS *src,
                                  BACNET_CONFIRMED_SERVICE_ACK_DATA *service_data);

// Error-Handers
void MyRejectHandler(BACNET_ADDRESS *src,
                    uint8_t invoke_id,
                    uint8_t reject_reason);

void MyAbortHandler(BACNET_ADDRESS *src,
                    uint8_t invoke_id,
                    uint8_t abort_reason,
                    bool server);

void MyErrorHandler(BACNET_ADDRESS *src,
                           uint8_t invoke_id,
                           BACNET_ERROR_CLASS error_class,
                           BACNET_ERROR_CODE error_code);

#endif
