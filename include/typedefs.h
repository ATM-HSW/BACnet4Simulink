#ifndef _TYPE_DEFINITIONS_H_
#define _TYPE_DEFINITIONS_H_

/*----------*/
/* Includes */
/*----------*/
#include <stdint.h>


/*-----------------*/
/* Typedefinitions */
/*-----------------*/
typedef enum SS_BLOCKTYPES
{
  SS_BLOCKTYPE_CONFIG = 0,
  SS_BLOCKTYPE_READBLOCK,
  SS_BLOCKTYPE_WRITEBLOCK,
  SS_BLOCKTYPE_SUBSCRBLOCK,
  
  SS_BLOCKTYPE_CNT,  
} SS_BLOCKTYPES_t;

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
