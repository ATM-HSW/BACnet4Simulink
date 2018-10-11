#define S_FUNCTION_NAME sfun_Bacnet /* Defines and Includes */
#define S_FUNCTION_LEVEL 2

/*----------*/
/* Includes */
/*----------*/
#include "simstruc.h"

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


/*---------*/
/* Defines */
/*---------*/


/*-----------------*/
/* Typedefinitions */
/*-----------------*/


/*------------------*/
/* Global Variables */
/*------------------*/
/* the invoke id is needed to filter incoming messages */
static BACNET_ADDRESS Target_Address;
static uint8_t Rx_Buf[MAX_MPDU] = { 0 };
static uint32_t max_apdu = 0;

uint32_t num_Key_Map = 0;
READ_KEY_MAP *Key_Map[255];

uint32_t num_Subscriptions = 0;
SUBSCRIBE_KEY_MAP *S_Key_Map[255];


/*----------------------*/
/* Simulink - sFunction */
/*----------------------*/
#define MDL_INITIALIZE_CONDITIONS
#define MDL_START

static void mdlInitializeSizes(SimStruct *S)
{
    ssSetNumSFcnParams(S, SS_PARAMETER_CNT);

    if (ssGetNumSFcnParams(S) != ssGetSFcnParamsCount(S))
    {
        /* Parameter mismatch reported by the Simulink engine*/
        return;
    }

    ssSetSFcnParamTunable(S, SS_PARAMETER_BLOCK_TYPE, 0);             //BlockType
    ssSetSFcnParamTunable(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE, 0); //Target Device Instance
    ssSetSFcnParamTunable(S, SS_PARAMETER_OBJECT_TYPE, 0);            //Object Type
    ssSetSFcnParamTunable(S, SS_PARAMETER_OBJECT_INSTANCE, 0);        //Object Instance
    ssSetSFcnParamTunable(S, SS_PARAMETER_INTERFACE, 0);              //Interface
    ssSetSFcnParamTunable(S, SS_PARAMETER_WRITE_PRIORITY, 0);         //Write Priority

    /* Config Block */
    if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
    {
        if (!ssSetNumInputPorts(S, 0))  { return; }
        if (!ssSetNumOutputPorts(S, 0)) { return; }
    }

    /* Read Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
    {
        if (!ssSetNumInputPorts(S, 0))  { return; }
        if (!ssSetNumOutputPorts(S, 1)) { return; }

        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE) // Analog
        {
            ssSetOutputPortDataType(S, 0, SS_SINGLE);
        }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE) // Binary
        {
            ssSetOutputPortDataType(S, 0, SS_BOOLEAN);
        }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE) // MULTI_STATE_VALUE
        {
            ssSetOutputPortDataType(S, 0, SS_UINT32);
        }

        else
        {
            ssSetOutputPortDataType(S, 0, SS_DOUBLE);
        }

        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);

        ssSetNumIWork(S, 2); // for index of Key_Map entry, address bind success
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        if (!ssSetNumInputPorts(S, 1)) { return; }

        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE) // Analog
        { ssSetInputPortDataType(S, 0, SS_DOUBLE); }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE) // Binary
        { ssSetInputPortDataType(S, 0, SS_BOOLEAN); }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE) // MULTI_STATE_VALUE
        { ssSetInputPortDataType(S, 0, SS_UINT32); }

        else
        { ssSetInputPortDataType(S, 0, SS_DOUBLE); }

        ssSetInputPortWidth(S, 0, 1);
        ssSetInputPortDirectFeedThrough(S, 0, 1);
        ssSetInputPortComplexSignal(S, 0, COMPLEX_NO);

        if (!ssSetNumOutputPorts(S, 0)) { return; }

        ssSetNumIWork(S, 2); // for index of Key_Map entry, address bind success
    }

    /* Subscribe Read */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_SUBSCRBLOCK)
    {
        if (!ssSetNumInputPorts(S, 0))  { return; }
        if (!ssSetNumOutputPorts(S, 1)) { return; }

        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE) // Analog
        { ssSetOutputPortDataType(S, 0, SS_SINGLE); }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE) // Binary
        { ssSetOutputPortDataType(S, 0, SS_BOOLEAN); }

        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE) // MULTI_STATE_VALUE
        { ssSetOutputPortDataType(S, 0, SS_UINT32); }

        else
        { ssSetOutputPortDataType(S, 0, SS_DOUBLE); }

        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);

        ssSetNumIWork(S, 2); // for index of Key_Map entry, address bind success
    }

    /* One SampleTime for each Block at whole */
    ssSetNumSampleTimes(S, 1);

    /* Take care when specifying exception free code - see sfuntmpl.doc */
    ssSetOptions(S, 0);
    return;
}

#if defined(MATLAB_MEX_FILE) 
    static void mdlInitializeSampleTimes(SimStruct *S)
    {
        double sampleTime = mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_SAMPLE_TIME));
        
        // /* Specified Sample-Time for Config Block (Rx Funtionality) */
        // if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
        // {
        //     DEBUG_MSG("[SampleTime] Config... SS_BLOCKTYPE_CONFIG [0.1 0.0]");
        //     ssSetSampleTime(S, 0, 0.1);
        //     ssSetOffsetTime(S, 0, 0.0);
        //     return;
        // }

        // else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
        // {
        //    DEBUG_MSG("[SampleTime] Config... SS_BLOCKTYPE_WRITEBLOCK [INHERITED_SAMPLE_TIME 0.0]");
        //    ssSetSampleTime(S, 0, INHERITED_SAMPLE_TIME);
        //    ssSetOffsetTime(S, 0, 0.0);
        //    return;
        // }

        // /* Other Blocks are only called defined by inhertied Sample Time */
        // else
        // {
            DEBUG_MSG("[SampleTime] BlockType (%u) [%f %f]",
                      (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)),
                      sampleTime,
                      0.0);
            
            if      (sampleTime == -1) { ssSetSampleTime(S, 0, INHERITED_SAMPLE_TIME); }
            else if (sampleTime == 0)  { ssSetSampleTime(S, 0, CONTINUOUS_SAMPLE_TIME); }
            else                       { ssSetSampleTime(S, 0, sampleTime); }

            ssSetOffsetTime(S, 0, 0.0);
            return;
        // }
        
        DEBUG_MSG("[ERROR] - [SampleTime] Config... FAIL");
        return;
    }
#endif

#if defined(MDL_INITIALIZE_CONDITIONS)
    static void mdlInitializeConditions(SimStruct *S)
    {
        char host[16];
        

        /* ConfigBlock */
        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
        {
            mxGetString(ssGetSFcnParam(S, SS_PARAMETER_INTERFACE), host, 16);

            DEBUG_MSG("[INIT] --ConfigBlock--");
            DEBUG_MSG("[INIT] ConfigBlock (HOST): %s", host);

            Init_Service_Handlers();
            bip_set_port(htons(0xBAC0));

            if (!datalink_init(host))
            {
                DEBUG_MSG("[INIT] Failed to init BIP");
                exit(1);
            }

            atexit(datalink_cleanup);
            Send_WhoIs(-1, -1);
        }

        /* ReadBlock */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
        {
            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            ssGetIWork(S)[0] = num_Key_Map;
            Key_Map[num_Key_Map++] = (READ_KEY_MAP *)calloc(1, sizeof(READ_KEY_MAP));

            ssGetIWork(S)[1] = (uint32_t)address_bind_request(
                Target_Device_Instance,
                &max_apdu,
                &Target_Address);

            DEBUG_MSG("[INIT] --ReadBlock--");
            DEBUG_MSG("[INIT] Binding... %s", (ssGetIWork(S)[1] > 0) ? "OK" : "FAIL");
        }

        /* WriteBlock */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
        {
            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            ssGetIWork(S)[1] = (uint32_t)address_bind_request(
                Target_Device_Instance,
                &max_apdu,
                &Target_Address);

            DEBUG_MSG("[INIT] --WriteBlock--");
            DEBUG_MSG("[INIT] Binding... %s", (ssGetIWork(S)[1] > 0) ? "OK" : "FAIL");
        }

        /* SubscribeCoV Block */
        else
        {
            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            ssGetIWork(S)[0] = num_Subscriptions;
            S_Key_Map[num_Subscriptions++] = (SUBSCRIBE_KEY_MAP *)calloc(1, sizeof(SUBSCRIBE_KEY_MAP));

            ssGetIWork(S)[1] = (uint32_t)address_bind_request(
                Target_Device_Instance,
                &max_apdu,
                &Target_Address);

            S_Key_Map[ssGetIWork(S)[0]]->process_ID = num_Subscriptions;

            DEBUG_MSG("[INIT] --SubscriptionBlock--");
            DEBUG_MSG("[INIT] Binding... %s", (ssGetIWork(S)[1] > 0) ? "OK" : "FAIL");
        }

        return;
    }
#endif /* MDL_INITIALIZE_CONDITIONS */


#if defined(MDL_START)
    static void mdlStart(SimStruct *S)
    {
        num_Key_Map = 0;
        num_Subscriptions = 0;
        address_init();
    }
#endif

static void mdlOutputs(SimStruct *S, int_T tid)
{
    uint16_t pdu_len = 0;
    BACNET_ADDRESS src = {0};
    BACNET_APPLICATION_DATA_VALUE write_data;
    BACNET_SUBSCRIBE_COV_DATA cov_data;
    real32_T *yr; // = (real_T*)ssGetOutputPortSignal(S,0);
    bool *yb;     // = (bool*)ssGetOutputPortSignal(S,0);
    uint32_T *yu; // = (uint32_T*)ssGetOutputPortSignal(S,0);
    InputRealPtrsType u;

    /* Config Block */
    if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
    {
        do /* process */
        {
            pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, 10);
            if (pdu_len) { npdu_handler(&src, &Rx_Buf[0], pdu_len); }
        } while (pdu_len > 0);
    }

    /* Read Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
    {
        uint32_t Target_Device_Instance =
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

        if (ssGetIWork(S)[1] == 0)
        {
            ssGetIWork(S)[1] = (uint32_t)address_bind_request(
                Target_Device_Instance,
                &max_apdu,
                &Target_Address);

            DEBUG_MSG("[READBLOCK] Address bind for device (%u)... %s",
                      Target_Device_Instance,
                      (ssGetIWork(S)[1] != 0) ? "OK" : "FAIL");
        }

        if ((ssGetIWork(S)[1] != 0) && (Key_Map[ssGetIWork(S)[0]]->invoke_ID == 0))
        {
            Key_Map[ssGetIWork(S)[0]]->invoke_ID = Send_Read_Property_Request(
                Target_Device_Instance,
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)),
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE)),
                PROP_PRESENT_VALUE, BACNET_ARRAY_ALL);

            DEBUG_MSG("[READBLOCK] Sent RP request (%i) (%u|%u|%u|%s)",
                      Key_Map[ssGetIWork(S)[0]]->invoke_ID,
                      Target_Device_Instance,
                      (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)),
                      (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE)),
                      "PV");
        }

        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE) // Analog
        {
            yr = (real32_T *)ssGetOutputPortSignal(S, 0);
            *yr = (real32_T)Key_Map[ssGetIWork(S)[0]]->data.Real;
        }
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE) // Binary
        {
            yb = (bool *)ssGetOutputPortSignal(S, 0);
            *yb = Key_Map[ssGetIWork(S)[0]]->data.Boolean;
        }
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE) // Multistate
        {
            yu = (uint32_T *)ssGetOutputPortSignal(S, 0);
            *yu = Key_Map[ssGetIWork(S)[0]]->data.Enumerated;
        }
        else
        {
            DEBUG_MSG("[mdlOutputs_Read] Undefined ObjectType %u", (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)));
            DEBUG_MSG("[mdlOutputs_Read] Reverting to Datatybe 'Real'");

            yb = (bool *)ssGetOutputPortSignal(S, 0);
            *yb = Key_Map[ssGetIWork(S)[0]]->data.Real;
        }
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        uint32_t Target_Device_Instance =
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

        uint32_t Target_Object_Type = 
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));

        uint32_t Target_Object_Instance =
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));

        if (ssGetIWork(S)[1] == 0)
            ssGetIWork(S)[1] = (uint32_t)address_bind_request(
                Target_Device_Instance,
                &max_apdu, &Target_Address);

        DEBUG_MSG("[WRITEBLOCK] Address bind for device (%u)... %s",
                  Target_Device_Instance,
                  (ssGetIWork(S)[1] != 0) ? "OK" : "FAIL");

        write_data.next = NULL;
        write_data.context_specific = false;

        u = ssGetInputPortRealSignalPtrs(S, 0);

        if (Target_Object_Type == OBJECT_ANALOG_INPUT ||
            Target_Object_Type == OBJECT_ANALOG_OUTPUT ||
            Target_Object_Type == OBJECT_ANALOG_VALUE) // Analog
        {
            write_data.tag = BACNET_APPLICATION_TAG_REAL;
            write_data.type.Real = (float)*u[0];
        }

        else if (Target_Object_Type == OBJECT_BINARY_INPUT ||
                 Target_Object_Type == OBJECT_BINARY_OUTPUT ||
                 Target_Object_Type == OBJECT_BINARY_VALUE) // Binary
        {
            write_data.tag = BACNET_APPLICATION_TAG_ENUMERATED;
            if (*u[0])
            {
                write_data.type.Enumerated = BINARY_ACTIVE;
            }
            else
            {
                write_data.type.Enumerated = BINARY_INACTIVE;
            }
        }

        else if (Target_Object_Type == OBJECT_MULTI_STATE_VALUE) // Multistate
        {
            write_data.tag = BACNET_APPLICATION_TAG_UNSIGNED_INT;
            write_data.type.Unsigned_Int = (uint32_t)*u[0];
        }

        else
        {
            DEBUG_MSG("[mdlOutputs_Write] Undefined ObjectType %u", Target_Object_Type);
            DEBUG_MSG("[mdlOutputs_Write] Reverting to Datatybe 'Double'");

            write_data.tag = BACNET_APPLICATION_TAG_DOUBLE;
            write_data.type.Double = (double)*u[0];
        }

        if (ssGetIWork(S)[1] != 0)
        {
            Send_Write_Property_Request(
                Target_Device_Instance,
                Target_Object_Type,
                Target_Object_Instance,
                PROP_PRESENT_VALUE,
                &write_data,
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_WRITE_PRIORITY)), BACNET_ARRAY_ALL);

            DEBUG_MSG("[WRITEBLOCK] Sent WP request (%u|%u|%u|%s)",
                      Target_Device_Instance,
                      Target_Object_Type,
                      Target_Object_Instance,
                      "PV");
        }
    }

    /* SubscribeCoV Block */
    else
    {
        uint32_t Target_Device_Instance = 
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

        uint32_t Device_Object_Type = 
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));

        if (ssGetIWork(S)[1] == 0)
        { ssGetIWork(S)[1] = (uint32_t)address_bind_request(Target_Device_Instance, &max_apdu, &Target_Address); }

        /* Send subscription request */
        if (ssGetIWork(S)[1] == 1)
        {
            cov_data.monitoredObjectIdentifier.type = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));
            cov_data.monitoredObjectIdentifier.instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));
            cov_data.subscriberProcessIdentifier = S_Key_Map[ssGetIWork(S)[0]]->process_ID;
            cov_data.cancellationRequest = false;
            cov_data.issueConfirmedNotifications = false;
            cov_data.lifetime = 100;

            uint8_t cov = Send_COV_Subscribe(Target_Device_Instance, &cov_data);

            DEBUG_MSG("[SUBSCRBLOCK] Subscription on device (%u)... %s", 
                      Target_Device_Instance, 
                      (cov > 0) ? "OK" : "FAIL");

            ssGetIWork(S)[1] = 2;
        }

        /* copy received values to output port */
        else
        {
            if (Device_Object_Type == OBJECT_ANALOG_INPUT ||
                Device_Object_Type == OBJECT_ANALOG_OUTPUT ||
                Device_Object_Type == OBJECT_ANALOG_VALUE) // Analog
            {
                yr = (real32_T *)ssGetOutputPortSignal(S, 0);
                *yr = (real32_T)S_Key_Map[ssGetIWork(S)[0]]->data.Real;
            }

            else if (Device_Object_Type == OBJECT_BINARY_INPUT ||
                     Device_Object_Type == OBJECT_BINARY_OUTPUT ||
                     Device_Object_Type == OBJECT_BINARY_VALUE) // Binary
            {
                yb = (bool *)ssGetOutputPortSignal(S, 0);
                *yb = S_Key_Map[ssGetIWork(S)[0]]->data.Boolean;
            }

            else if (Device_Object_Type == OBJECT_MULTI_STATE_VALUE) // Multistate
            {
                yu = (uint32_T *)ssGetOutputPortSignal(S, 0);
                *yu = S_Key_Map[ssGetIWork(S)[0]]->data.Enumerated;
            }

            else
            {
                DEBUG_MSG("[mdlOutputs_Subscr] Undefined ObjectType %u", Device_Object_Type);
                DEBUG_MSG("[mdlOutputs_Subscr] Reverting to Datatybe 'Real'");

                yu = (uint32_T*)ssGetOutputPortSignal(S, 0);
                *yu = (uint32_T)S_Key_Map[ssGetIWork(S)[0]]->data.Real;
            }
        }
    }

    return;
}

static void mdlTerminate(SimStruct *S)
{
    BACNET_APPLICATION_DATA_VALUE write_data;
    BACNET_SUBSCRIBE_COV_DATA cov_data;

    /* Config Block */
    if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
    {
        DEBUG_MSG("[Terminate] ConfigBlock");

        datalink_cleanup();
        atexit(datalink_cleanup);
    }

    /* Read Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
    {
        DEBUG_MSG("[Terminate] ReadBlock");

        free(Key_Map[ssGetIWork(S)[0]]);
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        DEBUG_MSG("[Terminate] WriteBlock");

        write_data.next = NULL;
        write_data.context_specific = false;

        write_data.tag = BACNET_APPLICATION_TAG_NULL;
        write_data.type.Enumerated = BINARY_INACTIVE;

        Send_Write_Property_Request(
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE)),
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)),
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE)),
            PROP_PRESENT_VALUE, &write_data,
            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_WRITE_PRIORITY)),
            BACNET_ARRAY_ALL);
    }

    /* SubscribeCoV Block */
    else
    {
        DEBUG_MSG("[Terminate] SubscribeBlock");

        cov_data.monitoredObjectIdentifier.type = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));
        cov_data.monitoredObjectIdentifier.instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));
        cov_data.subscriberProcessIdentifier = S_Key_Map[ssGetIWork(S)[0]]->process_ID;
        cov_data.cancellationRequest = true;
        cov_data.issueConfirmedNotifications = false;
        cov_data.lifetime = 100;

        Send_COV_Subscribe((uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE)), &cov_data);

        free(S_Key_Map[ssGetIWork(S)[0]]);
    }

    return;
}

#ifdef MATLAB_MEX_FILE /* Is this file being compiled as a MEX-file? */
    #include "simulink.c"  /* MEX-file interface mechanism */
#else
    #include "cg_sfun.h" /* Code generation registration function */
#endif
