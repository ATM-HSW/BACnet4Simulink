#define S_FUNCTION_NAME sfun_Bacnet /* Defines and Includes */
#define S_FUNCTION_LEVEL 2

#include "simstruc.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>       /* for time */

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


static uint8_t Rx_Buf[MAX_MPDU] = { 0 };

typedef struct Read_Key_Map{
	uint8_t invoke_ID;
	uint8_t type;
	union{
		bool Boolean;
		uint32_t Enumerated;
		float Real;
	}data;
}READ_KEY_MAP;

typedef struct Subscribe_Key_Map{
    uint32_t    process_ID;
    union{
        bool Boolean;
        uint32_t Enumerated;
        float Real;
    }data;
}SUBSCRIBE_KEY_MAP;

uint32_t num_Key_Map=0;
READ_KEY_MAP *Key_Map[255];

uint32_t num_Subscriptions=0;
SUBSCRIBE_KEY_MAP *S_Key_Map[255];

static uint32_t Target_Device_Object_Instance = BACNET_MAX_INSTANCE;
static uint32_t Target_Object_Instance = BACNET_MAX_INSTANCE;
static BACNET_PROPERTY_ID Target_Object_Property = PROP_ACKED_TRANSITIONS;

/* the invoke id is needed to filter incoming messages */
static BACNET_ADDRESS Target_Address;

static uint32_t max_apdu=0;


static void MyErrorHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    BACNET_ERROR_CLASS error_class,
    BACNET_ERROR_CODE error_code)
{
//     if (address_match(&Target_Address, src) &&
//         (invoke_id == Request_Invoke_ID)) {
//         printf("BACnet Error: %s: %s\r\n",
//             bactext_error_class_name((int) error_class),
//             bactext_error_code_name((int) error_code));
//         Error_Detected = true;
//     }
}

void MyAbortHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t abort_reason,
    bool server)
{
//     (void) server;
//     if (address_match(&Target_Address, src) &&
//         (invoke_id == Request_Invoke_ID)) {
//         printf("BACnet Abort: %s\r\n",
//             bactext_abort_reason_name((int) abort_reason));
//         Error_Detected = true;
//     }
}

void MyRejectHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id,
    uint8_t reject_reason)
{
//     if (address_match(&Target_Address, src) &&
//         (invoke_id == Request_Invoke_ID)) {
//         printf("BACnet Reject: %s\r\n",
//             bactext_reject_reason_name((int) reject_reason));
//         Error_Detected = true;
//     }
}

void My_Read_Property_Ack_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src,
    BACNET_CONFIRMED_SERVICE_ACK_DATA * service_data)
{
    int len = 0;
    BACNET_READ_PROPERTY_DATA data;
	BACNET_APPLICATION_DATA_VALUE value;
    uint8_t *application_data;
    int application_data_len;
	uint32_t ii;
	
	for(ii=0; ii<num_Key_Map; ii++)
	{
		if(Key_Map[ii]->invoke_ID = service_data->invoke_id)
		{
			len = rp_ack_decode_service_request(service_request, service_len, &data);
			if (len > 0) 
			{
				application_data = data.application_data;
				application_data_len = data.application_data_len;
			
				len = bacapp_decode_application_data(application_data, (uint8_t) application_data_len, &value);

				if(len>0)
				{
					switch(value.tag)
					{
					case BACNET_APPLICATION_TAG_ENUMERATED:
						Key_Map[ii]->data.Boolean = value.type.Boolean;
						//printf("%d", Key_Map[ii]->data.Boolean);
						break;
					case BACNET_APPLICATION_TAG_UNSIGNED_INT:
						Key_Map[ii]->data.Enumerated = value.type.Unsigned_Int;
						//printf("%d", Key_Map[ii]->data.Enumerated);
						break;
					case BACNET_APPLICATION_TAG_REAL:
						Key_Map[ii]->data.Real = value.type.Real;
						//printf("%f", Key_Map[ii]->data.Real);
						break;
					}
				}
			}
			tsm_invoke_id_free(Key_Map[ii]->invoke_ID);
            Key_Map[ii]->invoke_ID = 0;
            break;
		}
    }
}

void My_Unconfirmed_COV_Notification_Handler(
    uint8_t * service_request,
    uint16_t service_len,
    BACNET_ADDRESS * src)
{
	BACNET_COV_DATA cov_data;	
    BACNET_PROPERTY_VALUE property_value[2];
    BACNET_PROPERTY_VALUE *pProperty_value = NULL;
	uint32_t len;	    
	uint32_t ii;

	pProperty_value = &property_value[0];
    while (pProperty_value) {
        ii++;
        if (ii < 2) {
            pProperty_value->next = &property_value[ii];
        } else {
            pProperty_value->next = NULL;
        }
        pProperty_value = pProperty_value->next;
    }
    cov_data.listOfValues = &property_value[0];

	len = cov_notify_decode_service_request(service_request, service_len, &cov_data);

    if(len > 0)
    {
        for(ii = 0; ii<num_Subscriptions; ii++)
        {
            if(S_Key_Map[ii]->process_ID == cov_data.subscriberProcessIdentifier)
            {
                switch(cov_data.listOfValues->value.tag)
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
}

void MyWritePropertySimpleAckHandler(
    BACNET_ADDRESS * src,
    uint8_t invoke_id)
{
	tsm_invoke_id_free(invoke_id);
}

static void Init_Service_Handlers(
    void)
{
    //Device_Init(NULL);
    /* we need to handle who-is
       to support dynamic device binding to us */
    //apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_IS, handler_who_is);
    /* handle i-am to support binding to other devices */
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_I_AM, handler_i_am_bind);
    /* set the handler for all the services we don't implement
       It is required to send the proper reject message... */
    apdu_set_unrecognized_service_handler_handler
        (handler_unrecognized_service);
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
}

static void mdlInitializeSizes(SimStruct *S)
{
    ssSetNumSFcnParams(S, 6);
    if (ssGetNumSFcnParams(S) != ssGetSFcnParamsCount(S)) {
        return; /* Parameter mismatch reported by the Simulink engine*/
    }

    ssSetSFcnParamTunable(S, 0, 0);     //BlockType    
    ssSetSFcnParamTunable(S, 1, 0);     //Target Device Instance
    ssSetSFcnParamTunable(S, 2, 0);     //Object Type
    ssSetSFcnParamTunable(S, 3, 0);     //Object Instance
    ssSetSFcnParamTunable(S, 4, 0);     //Interface
    ssSetSFcnParamTunable(S, 5, 0);     //Write Priority
    
    if(mxGetScalar(ssGetSFcnParam(S,0)) == 0)   // Config Block
    {
        if (!ssSetNumInputPorts(S, 0)) return;

        if (!ssSetNumOutputPorts(S,0)) return;
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 1)  // Read Block
    {
        if (!ssSetNumInputPorts(S, 0)) return;

        if (!ssSetNumOutputPorts(S,1)) return;
        
        if (mxGetScalar(ssGetSFcnParam(S,2)) < 3)
            ssSetOutputPortDataType(S, 0, SS_SINGLE);
        else if (mxGetScalar(ssGetSFcnParam(S,2)) == 19)            
            ssSetOutputPortDataType(S, 0, SS_UINT32);
        else
            ssSetOutputPortDataType(S, 0, SS_BOOLEAN);
            
        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);
		
        ssSetNumIWork(S, 2);    // for index of Key_Map entry, address bind success
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 2)   // Write Block
    {
        if (!ssSetNumInputPorts(S, 1)) return;  
        
//         if (mxGetScalar(ssGetSFcnParam(S,2)) < 3)
//             ssSetInputPortDataType(S, 0, SS_SINGLE);
//         else if (mxGetScalar(ssGetSFcnParam(S,2)) == 19)            
//             ssSetInputPortDataType(S, 0, SS_UINT32);
//         else
//             ssSetInputPortDataType(S, 0, SS_DOUBLE);
        
        ssSetInputPortWidth(S, 0, 1);
        ssSetInputPortDirectFeedThrough(S, 0, 1);
        ssSetInputPortComplexSignal(S, 0, COMPLEX_NO);

        if (!ssSetNumOutputPorts(S,0)) return;
		
        ssSetNumIWork(S, 2);    // for index of Key_Map entry, address bind success        
    }
    else // Subscribe Read
    {
        if (!ssSetNumInputPorts(S, 0)) return;

        if (!ssSetNumOutputPorts(S,1)) return;
        
        if (mxGetScalar(ssGetSFcnParam(S,2)) < 3)
            ssSetOutputPortDataType(S, 0, SS_SINGLE);
        else if (mxGetScalar(ssGetSFcnParam(S,2)) == 19)            
            ssSetOutputPortDataType(S, 0, SS_UINT32);
        else
            ssSetOutputPortDataType(S, 0, SS_BOOLEAN);
            
        ssSetOutputPortWidth(S, 0, 1);
        ssSetOutputPortComplexSignal(S, 0, COMPLEX_NO);
		
        ssSetNumIWork(S, 2);    // for index of Key_Map entry, address bind success
    }
        

    ssSetNumSampleTimes(S, 1);
    

    /* Take care when specifying exception free code - see sfuntmpl.doc */
    ssSetOptions(S, 0);
    }
static void mdlInitializeSampleTimes(SimStruct *S)
{
    ssSetSampleTime(S, 0, INHERITED_SAMPLE_TIME);
    ssSetOffsetTime(S, 0, 0.0);
}

#define MDL_START

#if defined(MDL_START)
static void mdlStart(SimStruct *S)
{
    num_Key_Map = 0;
    num_Subscriptions = 0;
    address_init();
}
#endif

#define MDL_INITIALIZE_CONDITIONS  /*Change to #undef to remove */
                                    /*function*/
#if defined(MDL_INITIALIZE_CONDITIONS)
static void mdlInitializeConditions(SimStruct *S)
{
    char host[16];

    if(mxGetScalar(ssGetSFcnParam(S,0)) == 0)
    {
        mxGetString(ssGetSFcnParam(S, 4), host, 16);
        Init_Service_Handlers();
        bip_set_port(htons(0xBAC0));
        if(!datalink_init(host))
            exit(1);

        atexit(datalink_cleanup);

        Send_WhoIs(0, BACNET_MAX_INSTANCE);
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 1)
    {
        ssGetIWork(S)[0] = num_Key_Map;
        Key_Map[num_Key_Map++] = (READ_KEY_MAP*) calloc(1, sizeof(READ_KEY_MAP));
        ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 2)   // Write Block
    {
//         ssGetIWork(S)[0] = num_Key_Map;
//         Key_Map[num_Key_Map++] = (READ_KEY_MAP*) calloc(1, sizeof(READ_KEY_MAP));
         ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
    }
    else // Subscribe Read
    {
        ssGetIWork(S)[0] = num_Subscriptions;
        S_Key_Map[num_Subscriptions++] = (SUBSCRIBE_KEY_MAP*) calloc(1, sizeof(SUBSCRIBE_KEY_MAP));
        ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
        S_Key_Map[ssGetIWork(S)[0]]->process_ID = num_Subscriptions;
    }
}
#endif /* MDL_INITIALIZE_CONDITIONS */

static void mdlOutputs(SimStruct *S, int_T tid)
{
    uint16_t pdu_len = 0;
    BACNET_ADDRESS src = {0};
	BACNET_APPLICATION_DATA_VALUE write_data;
    BACNET_SUBSCRIBE_COV_DATA cov_data;
    real32_T *yr;// = (real_T*)ssGetOutputPortSignal(S,0);    
    bool *yb;// = (bool*)ssGetOutputPortSignal(S,0);    
    uint32_T *yu;// = (uint32_T*)ssGetOutputPortSignal(S,0);
	InputRealPtrsType u;
    
    if(mxGetScalar(ssGetSFcnParam(S,0)) == 0)       // Config Block
    {
        
        do
        {
            pdu_len = datalink_receive(&src, &Rx_Buf[0], MAX_MPDU, 10);

            /* process */
            if (pdu_len) {
                npdu_handler(&src, &Rx_Buf[0], pdu_len);
            }
        }while(pdu_len > 0);
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 1)  // Read Block
    {
        if(ssGetIWork(S)[1] == 0)
            ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
        
        if((ssGetIWork(S)[1] != 0) && (Key_Map[ssGetIWork(S)[0]]->invoke_ID == 0))
        {
            Key_Map[ssGetIWork(S)[0]]->invoke_ID = Send_Read_Property_Request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,2)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,3)), PROP_PRESENT_VALUE, BACNET_ARRAY_ALL);
        }
        
        if(mxGetScalar(ssGetSFcnParam(S,2)) < 3) // Analog
        {
            yr = (real32_T*)ssGetOutputPortSignal(S,0);
            *yr = (real32_T)Key_Map[ssGetIWork(S)[0]]->data.Real;
        }
        else if(mxGetScalar(ssGetSFcnParam(S,2)) == 19) // Multistate
        {     
            yu = (uint32_T*)ssGetOutputPortSignal(S,0);
            *yu = Key_Map[ssGetIWork(S)[0]]->data.Enumerated;
        }
        else    // Binary
        {          
            yb = (bool*)ssGetOutputPortSignal(S,0);  
            *yb = Key_Map[ssGetIWork(S)[0]]->data.Boolean;
        }
    }
    else if(mxGetScalar(ssGetSFcnParam(S,0)) == 2)   // Write Block
    {
        if(ssGetIWork(S)[1] == 0)
            ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
        
		write_data.next = NULL;
		write_data.context_specific = false;

		u = ssGetInputPortRealSignalPtrs(S,0);

		if(mxGetScalar(ssGetSFcnParam(S,2)) < 3) // Analog
        {
			write_data.tag = BACNET_APPLICATION_TAG_REAL;
			write_data.type.Real = (float) *u[0];
        }
        else if(mxGetScalar(ssGetSFcnParam(S,2)) == 19) // Multistate
        {     			
			write_data.tag = BACNET_APPLICATION_TAG_UNSIGNED_INT;
			write_data.type.Unsigned_Int = (uint32_t) *u[0];
        }
        else    // Binary
        {            
			write_data.tag = BACNET_APPLICATION_TAG_ENUMERATED;
            if(*u[0])
                write_data.type.Enumerated = BINARY_ACTIVE;
            else
                write_data.type.Enumerated = BINARY_INACTIVE;                
        }

        if(ssGetIWork(S)[1] != 0)
        {
            Send_Write_Property_Request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,2)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,3)), PROP_PRESENT_VALUE, &write_data, (uint32_t)mxGetScalar(ssGetSFcnParam(S,5)), BACNET_ARRAY_ALL);
        }
    }
    else // Subscribe Read
    {
        if(ssGetIWork(S)[1] == 0)
            ssGetIWork(S)[1] = (uint32_t) address_bind_request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &max_apdu, &Target_Address);
        
        if(ssGetIWork(S)[1] == 1) // Send subscription request
        {
            cov_data.monitoredObjectIdentifier.type = (uint32_t)mxGetScalar(ssGetSFcnParam(S,2));
            cov_data.monitoredObjectIdentifier.instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S,3));
            cov_data.subscriberProcessIdentifier = S_Key_Map[ssGetIWork(S)[0]]->process_ID;
            cov_data.cancellationRequest = false;
            cov_data.issueConfirmedNotifications = false;
            cov_data.lifetime = 100;
            
            Send_COV_Subscribe((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &cov_data);
            
            ssGetIWork(S)[1] = 2;
        }
        else    // copy received values to output port
        {
            if(mxGetScalar(ssGetSFcnParam(S,2)) < 3) // Analog
            {
                yr = (real32_T*)ssGetOutputPortSignal(S,0);
                *yr = (real32_T)S_Key_Map[ssGetIWork(S)[0]]->data.Real;
            }
            else if(mxGetScalar(ssGetSFcnParam(S,2)) == 19) // Multistate
            {     
                yu = (uint32_T*)ssGetOutputPortSignal(S,0);
                *yu = S_Key_Map[ssGetIWork(S)[0]]->data.Enumerated;
            }
            else    // Binary
            {          
                yb = (bool*)ssGetOutputPortSignal(S,0);  
                *yb = S_Key_Map[ssGetIWork(S)[0]]->data.Boolean;
            }
        }
    }
}

static void mdlTerminate(SimStruct *S)
{	
	BACNET_APPLICATION_DATA_VALUE write_data;
    BACNET_SUBSCRIBE_COV_DATA cov_data;
	

	if(mxGetScalar(ssGetSFcnParam(S,0)) == 0)       // Config Block
    {
		datalink_cleanup();
	}
	else if(mxGetScalar(ssGetSFcnParam(S,0)) == 1)       // Read Block
    {
		free(Key_Map[ssGetIWork(S)[0]]);
	}
	else if(mxGetScalar(ssGetSFcnParam(S,0)) == 2)   // Write Block
	{
		write_data.next = NULL;
		write_data.context_specific = false;

          
		write_data.tag = BACNET_APPLICATION_TAG_NULL;
        write_data.type.Enumerated = BINARY_INACTIVE;

// 		free(Key_Map[ssGetIWork(S)[0]]);
		Send_Write_Property_Request((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,2)), (uint32_t)mxGetScalar(ssGetSFcnParam(S,3)), PROP_PRESENT_VALUE, &write_data, (uint32_t)mxGetScalar(ssGetSFcnParam(S,5)), BACNET_ARRAY_ALL);        
	}
    else    // Subscribe Read
    {
        cov_data.monitoredObjectIdentifier.type = (uint32_t)mxGetScalar(ssGetSFcnParam(S,2));
        cov_data.monitoredObjectIdentifier.instance = (uint32_t)mxGetScalar(ssGetSFcnParam(S,3));
        cov_data.subscriberProcessIdentifier = S_Key_Map[ssGetIWork(S)[0]]->process_ID;
        cov_data.cancellationRequest = true;
        cov_data.issueConfirmedNotifications = false;
        cov_data.lifetime = 100;

        Send_COV_Subscribe((uint32_t)mxGetScalar(ssGetSFcnParam(S,1)), &cov_data);

        free(S_Key_Map[ssGetIWork(S)[0]]);
    }
}

#ifdef MATLAB_MEX_FILE /* Is this file being compiled as a MEX-file? */
#include "simulink.c" /* MEX-file interface mechanism */
#else
#include "cg_sfun.h" /* Code generation registration function */
#endif