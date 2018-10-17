#define S_FUNCTION_NAME sfun_Bacnet /* Defines and Includes */
#define S_FUNCTION_LEVEL 2

/*----------*/
/* Includes */
/*----------*/
// MATLAB / Simulink
#include "simstruc.h"
#include "matrix.h"

// System
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

// BACnet Stack
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

// Project
#include "bacnet_initHandler.h"
#include "bacnet_myHandler.h"
#include "dbg_message.h"
#include "typedefs.h"

#include "macros.h"


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

        /* Analog Objects */
        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE)
        {
            ssSetOutputPortDataType(S, 0, SS_SINGLE);
        }

        /* Binary Objects */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE)
        {
            ssSetOutputPortDataType(S, 0, SS_BOOLEAN);
        }

        /* MultiSateValue Object */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE)
        {
            ssSetOutputPortDataType(S, 0, SS_UINT32);
        }

        /* Other */
        else
        {
            ssSetOutputPortDataType(S, 0, SS_DOUBLE);
            DEBUG_MSG("[WARN] Unknown ObjectType...");
        }

        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);

        ssSetNumIWork(S, SS_IWORK_RD_CNT);
        ssSetNumPWork(S, SS_PWORK_RD_CNT);
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        if (!ssSetNumInputPorts(S, 1)) { return; }

        /* Analog Objects */
        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE)
        { ssSetInputPortDataType(S, 0, SS_DOUBLE); }

        /* Binary Objects */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE)
        { ssSetInputPortDataType(S, 0, SS_BOOLEAN); }

        /* MultiStateValue Objects */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE)
        { ssSetInputPortDataType(S, 0, SS_UINT32); }

        /* Other */
        else
        { 
            ssSetInputPortDataType(S, 0, SS_DOUBLE);
            DEBUG_MSG("[WARN] Unknown ObjectType...");
        }

        ssSetInputPortWidth(S, 0, 1);
        ssSetInputPortDirectFeedThrough(S, 0, 1);
        ssSetInputPortComplexSignal(S, 0, COMPLEX_NO);

        if (!ssSetNumOutputPorts(S, 0)) { return; }

        ssSetNumIWork(S, SS_IWORK_WR_CNT);
    }

    /* Subscribe Read */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_SUBSCRBLOCK)
    {
        if (!ssSetNumInputPorts(S, 0))  { return; }
        if (!ssSetNumOutputPorts(S, 1)) { return; }

        /* Analog Objects */
        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_INPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_OUTPUT ||
            mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_ANALOG_VALUE)
        { ssSetOutputPortDataType(S, 0, SS_SINGLE); }

        /* Binary Objets */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_INPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_OUTPUT ||
                 mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_BINARY_VALUE)
        { ssSetOutputPortDataType(S, 0, SS_BOOLEAN); }

        /* MultiStateValue Object */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE)) == OBJECT_MULTI_STATE_VALUE)
        { ssSetOutputPortDataType(S, 0, SS_UINT32); }

        else
        { 
            ssSetOutputPortDataType(S, 0, SS_DOUBLE);
            DEBUG_MSG("[WARN] Unknown ObjectType...");
        }

        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);

        ssSetNumIWork(S, SS_IWORK_COV_CNT);
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

        #if defined(DEBUG)
            char blockType_str[16];
            
            switch ((uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)))
            {
                case SS_BLOCKTYPE_CONFIG:
                strncpy_s(blockType_str, LENGTH(blockType_str), "CONFIGBLOCK", sizeof("CONFIGBLOCK"));
                break;

                case SS_BLOCKTYPE_READBLOCK:
                strncpy_s(blockType_str, LENGTH(blockType_str), "READBLOCK", sizeof("READBLOCK"));
                break;

                case SS_BLOCKTYPE_WRITEBLOCK:
                strncpy_s(blockType_str, LENGTH(blockType_str), "WRITEBLOCK", sizeof("WRITEBLOCK"));
                break;

                case SS_BLOCKTYPE_SUBSCRBLOCK:
                strncpy_s(blockType_str, LENGTH(blockType_str), "COVBLOCK", sizeof("COVBLOCK"));
                break;
            }
        #endif

        // In accordance to BlockMask define SampleTime
        // INHERITED_SAMPLE_TIME
        if(sampleTime == -1)
        {
            DEBUG_MSG("[%s] SampleTime: INHERITED", blockType_str);
            ssSetSampleTime(S, 0, INHERITED_SAMPLE_TIME);
        }

        // CONTINOUS_SAMPLE_TIME
        else if (sampleTime == 0)
        {
            DEBUG_MSG("[%s] SampleTime: CONTINOUS", blockType_str);
            ssSetSampleTime(S, 0, CONTINUOUS_SAMPLE_TIME);
        }

        // DISCRETE_SAMPLE_TIME
        else
        {
            DEBUG_MSG("[%s] SampleTime: DISCRETE", blockType_str);
            ssSetSampleTime(S,0, sampleTime);
        }
        
        // Define OffsetTime
        ssSetOffsetTime(S, 0, 0.0);
    }
#endif


#if defined(MDL_INITIALIZE_CONDITIONS)
    static void mdlInitializeConditions(SimStruct *S)
    {
        char host[16];
        
        /* ConfigBlock */
        if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
        {
            mxGetString(ssGetSFcnParam(S, SS_PARAMETER_INTERFACE), host, LENGTH(host));

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

            // Check for all BACnet devices currently available in this Network
            Send_WhoIs(-1, -1);
        }

        /* ReadBlock */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
        {
            DEBUG_MSG("[INIT] --ReadBlock--");

            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            DEBUG_MSG("  Target Device: %u", Target_Device_Instance);
            
            // Define Blocks NumKey (Identification)
            ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP] = num_Key_Map; // Make sure each ReadBlock call increases the counter
            Key_Map[num_Key_Map++] = (READ_KEY_MAP *)calloc(1, sizeof(READ_KEY_MAP));

            // Try to bind Block's TargetID
            ssGetIWork(S)[SS_IWORK_RD_BOUND] = 
                (uint32_t)address_bind_request(Target_Device_Instance,
                                               &max_apdu,
                                               &Target_Address);
            
            DEBUG_MSG("[INIT] Binding... %s", (ssGetIWork(S)[SS_IWORK_RD_BOUND] > 0) ? "OK" : "FAILED");

            // Reset individual Block read-CallCounter
            ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] = 0;

            // Init PWORK Arrays
            mxArray *tic[1];

            tic[0] = mxCreateDoubleMatrix(1,1, mxREAL);
            
            // Don't forget to destruct...
            mexMakeArrayPersistent(tic[0]);
            ssSetPWorkValue(S, SS_PWORK_RD_TIC, tic[0]);
        }

        /* WriteBlock */
        else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
        {
            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            ssGetIWork(S)[SS_IWORK_WR_BOUND] = (uint32_t)address_bind_request(Target_Device_Instance,
                                                              &max_apdu,
                                                              &Target_Address);

            DEBUG_MSG("[INIT] --WriteBlock--");
            DEBUG_MSG("[INIT] Binding... %s", (ssGetIWork(S)[SS_IWORK_WR_BOUND] > 0) ? "OK" : "FAILED");
        }

        /* SubscribeCoV Block */
        else
        {
            uint32_t Target_Device_Instance =
                (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));

            ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP] = num_Subscriptions;
            S_Key_Map[num_Subscriptions++] = (SUBSCRIBE_KEY_MAP *)calloc(1, sizeof(SUBSCRIBE_KEY_MAP));

            ssGetIWork(S)[SS_IWORK_COV_BOUND] = 
                (uint32_t)address_bind_request(Target_Device_Instance,
                                               &max_apdu,
                                               &Target_Address);

            S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->process_ID = num_Subscriptions;

            DEBUG_MSG("[INIT] --SubscriptionBlock--");
            DEBUG_MSG("[INIT] Binding... %s", (bool)ssGetIWork(S)[SS_IWORK_COV_BOUND] ? "OK" : "FAILED");
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
    BACNET_ADDRESS src = { 0 };
    BACNET_APPLICATION_DATA_VALUE write_data;
    BACNET_SUBSCRIBE_COV_DATA cov_data;
    InputRealPtrsType u;

    /* Config Block */
    if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_CONFIG)
    {
        do /* process */
        {
            pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, 10);
            
            if (pdu_len)
            {
                DEBUG_MSG("[ConfigBlock] Received BACnet message (%u)", pdu_len);
                npdu_handler(&src, &Rx_Buf[0], pdu_len);
            }
        } while (pdu_len > 0);

        return;
    }

    /* Read Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_READBLOCK)
    {
        // Target-Information
        uint32_t Target_Device_Instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));
        uint32_t Object_Type =            (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));
        uint32_t Object_Instance =        (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));

        // Block Information
        mxArray *tic[1];
        tic[0] = (mxArray*) ssGetPWorkValue(S, SS_PWORK_RD_TIC);

        // If unbound, bind Target_Device Address
        if (!(bool)ssGetIWork(S)[SS_IWORK_RD_BOUND])
        {
            ssGetIWork(S)[SS_IWORK_RD_BOUND] = 
                (uint32_t)address_bind_request(Target_Device_Instance,
                                               &max_apdu,
                                               &Target_Address);

            DEBUG_MSG("[READBLOCK] Address bind for device (%u)... %s",
                      Target_Device_Instance, ((bool)ssGetIWork(S)[SS_IWORK_RD_BOUND]) ? "OK" : "FAIL");
        }

        // On Timeout revode Invoke_ID
        if (Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->invoke_ID != 0)
        {
            mxArray *elapsed[1];
            elapsed[0] = mxCreateDoubleMatrix(1,1, mxREAL);

            // Get elapsed time since RP_Request
            mexCallMATLAB(1, elapsed, 1, tic, "toc");
            double *value = mxGetPr(elapsed[0]);

            // If Invoke_ID expired and at least 3 tries revoke ID
            if(ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] > 3 && *value >= 0.02)
            {
                Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->invoke_ID = 0;  // Revoke ID
                ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] = 0;                    // Reset Counter
            }
        }

        
        // If bound and not expecting Answer on InvokeID send Read_Property_Request
        if ((bool)ssGetIWork(S)[SS_IWORK_RD_BOUND] && Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->invoke_ID == 0)
        {
            Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->invoke_ID = 
                Send_Read_Property_Request(Target_Device_Instance,
                                           Object_Type,
                                           Object_Instance,
                                           PROP_PRESENT_VALUE, BACNET_ARRAY_ALL);

            // Reset CallCounter
            ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] = 0;

            // Start TimeMeasurement
            mexCallMATLAB(1, tic, 0, NULL, "tic");

            DEBUG_MSG("[READBLOCK] Sent RP request (%i) (%u|%u|%u|%s)",
                      Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->invoke_ID,
                      Target_Device_Instance,
                      Object_Type,
                      Object_Instance,
                      "PV");
        }

        /* Analog Objects */
        if (Object_Type == OBJECT_ANALOG_INPUT ||
            Object_Type == OBJECT_ANALOG_OUTPUT ||
            Object_Type == OBJECT_ANALOG_VALUE)
        {
            real32_T *y = (real32_T*)ssGetOutputPortSignal(S, 0);
            *y = (real32_T)Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->data.Real;
        }

        /* Binary Objects */
        else if (Object_Type == OBJECT_BINARY_INPUT ||
                 Object_Type == OBJECT_BINARY_OUTPUT ||
                 Object_Type == OBJECT_BINARY_VALUE)
        {
            bool *y = (bool *)ssGetOutputPortSignal(S, 0);
            *y = Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->data.Boolean;
        }

        /* MultiStateValue Object */
        else if (Object_Type == OBJECT_MULTI_STATE_VALUE)
        {
            uint32_T *y = (uint32_T *)ssGetOutputPortSignal(S, 0);
            *y = Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->data.Enumerated;
        }

        /* Other */
        else
        {
            DEBUG_MSG("[mdlOutputs_Read] Undefined ObjectType %u", Object_Type);
            DEBUG_MSG("[mdlOutputs_Read] Reverting to Datatype 'Real'");

            real32_T *y = (real32_T *)ssGetOutputPortSignal(S, 0);
            *y = Key_Map[ssGetIWork(S)[SS_IWORK_RD_NUM_KEYMAP]]->data.Real;
        }
        
        // Inkrement CallCounter with conditional reset
        ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] = 
            (ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] < 0xFFFFFFFF) ? ssGetIWork(S)[SS_IWORK_RD_READ_COUNTER] + 1 : 0;
        return;
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        //  Target-Information
        uint32_t Device_Instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));
        uint32_t Object_Type =     (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));
        uint32_t Object_Instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));
        uint32_t Object_Priority = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_WRITE_PRIORITY));

        // If unbound, bind Target_Device address
        if (!(bool)ssGetIWork(S)[SS_IWORK_WR_BOUND])
        {
            ssGetIWork(S)[SS_IWORK_WR_BOUND] = 
                address_bind_request(Device_Instance, &max_apdu, &Target_Address) ? 1 : 0;

            DEBUG_MSG("[WRITEBLOCK] Address bind for device (%u)... %s",
                      Device_Instance, ((bool)ssGetIWork(S)[SS_IWORK_WR_BOUND]) ? "FAIL" : "OK");
        }

        write_data.next = NULL;
        write_data.context_specific = false;

        u = ssGetInputPortRealSignalPtrs(S, 0);

        //
        // Configure WriteProperty Data & Type

        /*  Analog Objects */
        if (Object_Type == OBJECT_ANALOG_INPUT ||
            Object_Type == OBJECT_ANALOG_OUTPUT ||
            Object_Type == OBJECT_ANALOG_VALUE)
        {
            write_data.tag = BACNET_APPLICATION_TAG_REAL;
            write_data.type.Real = (float)(*u[0]);
        }

        /* Binary Objects */
        else if (Object_Type == OBJECT_BINARY_INPUT ||
                 Object_Type == OBJECT_BINARY_OUTPUT ||
                 Object_Type == OBJECT_BINARY_VALUE)
        {
            write_data.tag = BACNET_APPLICATION_TAG_BOOLEAN;
            if (*u[0]) { write_data.type.Boolean = BINARY_ACTIVE;   }
            else       { write_data.type.Boolean = BINARY_INACTIVE; }
        }

        /* MultiStateValue Object */
        else if (Object_Type == OBJECT_MULTI_STATE_VALUE)
        {
            write_data.tag = BACNET_APPLICATION_TAG_UNSIGNED_INT;
            write_data.type.Unsigned_Int = (uint32_t)(*u[0]);
        }

        /* Other */
        else
        {
            DEBUG_MSG("[mdlOutputs_Write] Undefined ObjectType %u", Object_Type);
            DEBUG_MSG("[mdlOutputs_Write] Reverting to Simulinkdefault 'Double'");

            write_data.tag = BACNET_APPLICATION_TAG_DOUBLE;
            write_data.type.Double = (double)(*u[0]);
        }

        // If address bound, send Write_Property_Request
        if ((bool)ssGetIWork(S)[SS_IWORK_WR_BOUND])
        {
            Send_Write_Property_Request(Device_Instance,
                                        Object_Type,
                                        Object_Instance,
                                        PROP_PRESENT_VALUE,
                                        &write_data,
                                        Object_Priority, BACNET_ARRAY_ALL);

            DEBUG_MSG("[WRITEBLOCK] Sent WP request (%u|%u|%u|%s)",
                      Device_Instance, Object_Type,
                      Object_Instance, "PV");
        }
    }

    /* SubscribeCoV Block */
    else
    {
        uint32_t Device_Instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE));
        uint32_t Object_Type =     (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_TYPE));
        uint32_t Object_Instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_OBJECT_INSTANCE));

        if ((bool)ssGetIWork(S)[SS_IWORK_COV_BOUND])
        { 
            ssGetIWork(S)[SS_IWORK_COV_BOUND] = 
                (uint32_t)address_bind_request(Device_Instance, &max_apdu, &Target_Address);

            DEBUG_MSG("[COVBLOCK] Address bind for device (%u)... %s",
                      Device_Instance, ((bool)ssGetIWork(S)[SS_IWORK_COV_BOUND]) ? "OK" : "FAIL");
        }

        // If address bound, send subscription request
        if ((bool)ssGetIWork(S)[SS_IWORK_COV_BOUND])
        {
            cov_data.monitoredObjectIdentifier.type = Object_Type;
            cov_data.monitoredObjectIdentifier.instance = Object_Instance;
            cov_data.subscriberProcessIdentifier = S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->process_ID;
            cov_data.cancellationRequest = false;
            cov_data.issueConfirmedNotifications = false;
            cov_data.lifetime = 100;

            uint8_t cov = Send_COV_Subscribe(Device_Instance, &cov_data);

            DEBUG_MSG("[SUBSCRBLOCK] Subscription on device (%u)... %s", 
                      Device_Instance, (cov > 0) ? "OK" : "FAIL");

            // Mark subscription as successful
            if(cov != 0) { ssGetIWork(S)[SS_IWORK_COV_BOUND] = 2; }
        }

        // if successfully subscribed, copy received values to output port
        else if (ssGetIWork(S)[SS_IWORK_COV_BOUND] == 2)
        {
            /* Analog Objects */
            if (Object_Type == OBJECT_ANALOG_INPUT ||
                Object_Type == OBJECT_ANALOG_OUTPUT ||
                Object_Type == OBJECT_ANALOG_VALUE)
            {
                real32_T *y = (real32_T *)ssGetOutputPortSignal(S, 0);
                *y = (real32_T)S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->data.Real;
            }

            /* Binary Objects */
            else if (Object_Type == OBJECT_BINARY_INPUT ||
                     Object_Type == OBJECT_BINARY_OUTPUT ||
                     Object_Type == OBJECT_BINARY_VALUE)
            {
                bool *y = (bool *)ssGetOutputPortSignal(S, 0);
                *y = S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->data.Boolean;
            }

            /* MultiStateValue Object */
            else if (Object_Type == OBJECT_MULTI_STATE_VALUE)
            {
                uint32_T *y = (uint32_T *)ssGetOutputPortSignal(S, 0);
                *y = S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->data.Enumerated;
            }

            /* Other */
            else
            {
                DEBUG_MSG("[mdlOutputs_Subscr] Undefined ObjectType %u", Object_Type);
                DEBUG_MSG("[mdlOutputs_Subscr] Reverting to Datatype 'Real'");

                real32_T *y = (real32_T *)ssGetOutputPortSignal(S, 0);
                *y = (real32_T)S_Key_Map[ssGetIWork(S)[SS_IWORK_COV_NUM_KEYMAP]]->data.Real;
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

        mxArray *tic[1];
        tic[0] = (mxArray*) ssGetPWorkValue(S, SS_PWORK_RD_TIC);
        mxDestroyArray(tic[0]);
    }

    /* Write Block */
    else if (mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_BLOCK_TYPE)) == SS_BLOCKTYPE_WRITEBLOCK)
    {
        DEBUG_MSG("[Terminate] WriteBlock");

        write_data.next = NULL;
        write_data.context_specific = false;

        write_data.tag = BACNET_APPLICATION_TAG_NULL;
        write_data.type.Enumerated = BINARY_INACTIVE;

        Send_Write_Property_Request((uint32_t)mxGetScalar(ssGetSFcnParam(S, SS_PARAMETER_TARGET_DEVICE_INSTANCE)),
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
