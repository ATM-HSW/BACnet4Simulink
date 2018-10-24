#ifndef _SFUN_BACNET_H_
#define _SFUN_BACNET_H_

/*----------*/
/* Includes */
/*----------*/
#include "bacnet_initHandler.h"
#include "bacnet_myHandler.h"
#include "dbg_message.h"
#include "typedefs.h"

#include "macros.h"


/*---------*/
/* Defines */
/*---------*/
#define KEYMAP_CNT    255
#define S_KEYMAP_CNT  255


/*--------------------*/
/* External Variables */
/*--------------------*/
#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t num_Key_Map;
extern READ_KEY_MAP *Key_Map[KEYMAP_CNT];

extern uint32_t num_Subscriptions;
extern SUBSCRIBE_KEY_MAP *S_Key_Map[S_KEYMAP_CNT];

#ifdef __cplusplus
}
#endif

/*------------*/
/* Prototypes */
/*------------*/
#ifdef __cplusplus
extern "C" {
#endif

void clear_InvokeID(uint8_t InvokeID);

#ifdef __cplusplus
}
#endif

#endif
