#ifndef _TYPE_DEFINITIONS_H_
#define _TYPE_DEFINITIONS_H_

/*----------*/
/* Includes */
/*----------*/
#include <stdint.h>


/*-----------------*/
/* Typedefinitions */
/*-----------------*/

//
// Blocktype Definitions
typedef enum SS_BLOCKTYPES
{
  SS_BLOCKTYPE_CONFIG = 0,
  SS_BLOCKTYPE_READBLOCK,
  SS_BLOCKTYPE_WRITEBLOCK,
  SS_BLOCKTYPE_SUBSCRBLOCK,
  
  SS_BLOCKTYPE_CNT,  
} SS_BLOCKTYPES_t;

//
// Parameter Definitions
typedef enum SS_PARAMETERS
{
    SS_PARAMETER_BLOCK_TYPE = 0,
    SS_PARAMETER_TARGET_DEVICE_INSTANCE,
    SS_PARAMETER_OBJECT_TYPE,
    SS_PARAMETER_OBJECT_INSTANCE,
    SS_PARAMETER_INTERFACE,
    SS_PARAMETER_WRITE_PRIORITY,
    SS_PARAMETER_SAMPLE_TIME,

    SS_PARAMETER_CNT,
} SS_PARAMETERS_t;

//
// S.IWORK Definitions
typedef enum SS_IWORK_RD
{
    SS_IWORK_RD_NUM_KEYMAP = 0,
    SS_IWORK_RD_BOUND,
    SS_IWORK_RD_READ_COUNTER,

    SS_IWORK_RD_CNT,
} SS_IWORK_RD_t;

typedef enum SS_IWORK_WR
{
    SS_IWORK_WR_PROC_ID = 0,
    SS_IWORK_WR_BOUND,

    SS_IWORK_WR_CNT,
} SS_IWORK_WR_t;

typedef enum SS_IWORK_COV
{
    SS_IWORK_COV_NUM_KEYMAP = 0,
    SS_IWORK_COV_BOUND,

    SS_IWORK_COV_CNT,
} SS_IWORK_COV_t;

//
// S.PWORK Definitions
typedef enum SS_PWORK_RD
{
    SS_PWORK_RD_TIC = 0,

    SS_PWORK_RD_CNT,
} SS_PWORK_RD_t;

//
// KeyMap Definitions
typedef struct Read_Key_Map
{
    uint8_t invoke_ID;
    uint8_t type;
    union {
        bool Boolean;
        uint32_t Enumerated;
        float Real;
    } data;
} READ_KEY_MAP;

typedef struct Subscribe_Key_Map
{
    uint32_t process_ID;
    union {
        bool Boolean;
        uint32_t Enumerated;
        float Real;
    } data;
} SUBSCRIBE_KEY_MAP;

#endif /*_ TYPE_DEFINITIONS_H_ */
