/**
 * @file user_cfg.h
 * @author LeandroKeenZapa
 * @brief 
 * @version 0.1
 * @date 2024-03-09
 * 
 * @copyright Copyright (c) 2024
 * 
 */


#ifndef USER_CFG_H
#define USER_CFG_H

#include "base_types.h"

/**
 * @brief X509 Version Support and Max Size
 * @note  LEGACY_VERSION is v1 type
*/

#define LEGACY_VERSION
#define CERT_BUFFER_MAX_SIZE    1028u

/**
 * @brief List of enabled verification
 * 
 * 
 */

#define ENABLE_VERSION_CHECK
#define ENABLE_SERIALNUMBER_CHECK
#define ENABLE_TIME_VALIDITY_CHECK
#define ENABLE_ISSUER_CHECK
#define ENABLE_SUBJECT_CHECK

/**
 * @brief List of trusted serialnumbers
 * 
 */
#define X509_SN_COUNT           (u1)5     
#define X509_SN_SIZE            (u1)7      
#define X509_SERIALNUMBER1      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define X509_SERIALNUMBER2      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }  
#define X509_SERIALNUMBER3      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }   
#define X509_SERIALNUMBER4      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }   
#define X509_SERIALNUMBER5      { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }   

/**
 * @brief Supported Signature Algorithm OID
 * 
*/

#define SIG_ALGO_OID_SIZE       (u1)7
#define SIG_ALGO_OID            { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }  

/**
 * @brief Chain of Trust CA subject
 * 
*/

#define COT_COUNTRY             "PH"
#define COT_ORG                 "ZAPA"
#define COT_CN                  "KEEN"


const u1 X509_SERIALNUMBER_LIST[][X509_SN_SIZE] = {
    X509_SERIALNUMBER1,
    X509_SERIALNUMBER2,
    X509_SERIALNUMBER3,
    X509_SERIALNUMBER4,
    X509_SERIALNUMBER5
};

const int X509_SERIALNUMBER_LIST_COUNT  = sizeof(X509_SERIALNUMBER_LIST)/X509_SN_SIZE;


#ifdef  LEGACY_VERSION
#define X509_VERSION1
#else
#define X509_VERSION3
#endif



#endif