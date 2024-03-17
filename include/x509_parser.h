/**
 * @file x509_parser.h  
 * @author LeandroKeenZapa
 * @brief 
 * @version 0.1
 * @date 2024-03-09
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#ifndef X509_PARSER_H
#define X509_PARSER_H

#include "base_types.h"

#define MAX_CERTIFICATES                1

#define LENGTH_BUFFER_SIZE          2       /* This means 2 bytes unsigned integer*/
#define ATTRIBUTE_BUFFER_SIZE       1024    /* Attribute buffer size.*/

/**
 * @brief DER Encoding of ASN.1 Types
 * 
 */

/*Bit Masks and Position Definitions*/
#define TAG_IMPLICIT_PRIMITIVE_MASK     (u1)0x80
#define TAG_IMPLICIT_CONSTRUCTED_MASK   (u1)0xA0

#define BYTE_MASK_1BIT              (u1)0b1
#define BYTE_MASK_2BITS             (u1)0b11
#define BYTE_MASK_5BITS             (u1)0b11111
#define BYTE_MASK_7BITS             (u1)0x7F

#define TAG_NUMBER_MASK             BYTE_MASK_5BITS

#define ENCODING_FORM_PRIMITIVE     (u1)0
#define ENCODING_FORM_CONSTRUCTED   (u1)1

#define ENCODING_FORM_BIT_POS       5
#define ENCODING_FORM_BIT_MASK      (u1)( BYTE_MASK_1BIT<<ENCODING_FORM_BIT_POS )

#define CLASS_BITS_POS              6
#define CLASS_BITS_MASK             (u1)( BYTE_MASK_2BITS<<CLASS_BITS_POS )

#define LENGTH_BASIC_MASK           BYTE_MASK_7BITS
#define LENGTH_EXTENDED_BIT_POS     7
#define LENGTH_EXTENDED_BIT_MASK    (u1)( BYTE_MASK_1BIT<<LENGTH_EXTENDED_BIT_POS )

#define LENGTH_EXTENDED_TRUE        1

#define BIT7_POS                    7
#define BIT7_MASK                   (u1)( BYTE_MASK_1BIT<<BIT7_POS )
/*end*/


/*Class Types*/
#define CLASS_UNIVERSAL             (u1)0b00
#define CLASS_APPLICATION           (u1)0b01
#define CLASS_CONTEXT_SPECIFIC      (u1)0b10
#define CLASS_PRIVATE               (u1)0b11
/*end*/

/*Universal Class Types*/
#define TAG_BOOLEAN                 (u1)0x01
#define TAG_INTEGER                 (u1)0x02
#define TAG_BITSTRING               (u1)0x03
#define TAG_OCTETSTRING             (u1)0x04
#define TAG_NULL                    (u1)0x05
#define TAG_OBJECTIDENTIFIER        (u1)0x06
#define TAG_UTF8STRING              (u1)0x0C
#define TAG_PRINTABLESTRING         (u1)0x13
#define TAG_TELETEXSTRING           (u1)0x14
#define TAG_IA5STRING               (u1)0x16
#define TAG_UTCTIME                 (u1)0x17
#define TAG_GENERALIZEDTIME         (u1)0x18
#define TAG_UNIVERSALSTRING         (u1)0x1C
#define TAG_BMPSTRING               (u1)0x1E
#define TAG_SEQUENCE                (u1)0x30
#define TAG_SET                     (u1)0x31
/*end*/

/*Other Types*/
#define DEFAULT_CLASS_TAGGING       CLASS_CONTEXT_SPECIFIC
#define TAG_ANY( class,encoding,number )    (u1)( ( class<<CLASS_BITS_POS ) |    \
                                            ( encoding<<ENCODING_FORM_BIT_POS) | \
                                            ( number&TAG_NUMBER_MASK ) )
#define TAG_CHOICE( number )                        TAG_ANY( CLASS_CONTEXT_SPECIFIC,ENCODING_FORM_CONSTRUCTED,number )
#define TAG_EXPLICIT( class,number )                TAG_ANY( class,ENCODING_FORM_CONSTRUCTED,number )
#define TAG_IMPLICIT( class,encoding,number )       TAG_ANY( class,encoding,number ) 
/*end*/


/**
 * @brief UTCtime supported formats. The defined values are the length of content in bytes.
 * 
*/
#define UTCTIME_OPT1_YYMMDDHHMMZ            11
#define UTCTIME_OPT2_YYMMDDHHMMSSZ          13
#define UTCTIME_OPT3_YYMMDDHHMM_HHMM        15
#define UTCTIME_OPT4_YYMMDDHHMMSS_HHMM      17





#define PARSE_SUCCESS                       (u1)1
#define PARSE_FAIL                          (u1)0

#define PARSE_FORMAT_ERR                    (u1)1
#define PARSE_SERIAL_ERR                    (u1)2
#define PARSE_ISSUER_ERR                    (u1)3
#define PARSE_VALIDITY_ERR                  (u1)4
#define PARSE_SUBJECT_ERR                   (u1)5
#define PARSE_SIGNATURE_ERR                 (u1)6

#define PARSE_READCONTENT_IDLE              (u1)0
#define PARSE_READCONTENT_READING           (u1)1
#define PARSE_READCONTENT_COMPLETE          (u1)2

#define PARSE_READLENGTH_IDLE               (u1)0
#define PARSE_READLENGTH_EXTENDED           (u1)1
#define PARSE_READLENGTH_COMPLETE           (u1)2

/*For the mean time, only 1 OID is supported for issuer and subject*/
#define OID_ISSUER_SUBJECT_CN_SIZE          (u1)3      
#define OID_ISSUER_SUBJECT_CN               { 0x55, 0x04, 0x03 }   

/*RSA with SHA256 OID */
#define OID_RSA_SHA256_SIZE                 (u1)9     
#define OID_RSA_SHA256                      { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B }

typedef enum {
    PARSE_ATTR_ABNORMAL_STATE ,
    PARSE_ATTR_CERT_STATE ,  
    PARSE_ATTR_TBSCERT_STATE ,  
    PARSE_ATTR_VERSION_EXPLICIT_STATE ,     
    PARSE_ATTR_VERSION_STATE ,           
    PARSE_ATTR_SERIAL_STATE,             
    PARSE_ATTR_SIGALGO_OID_STATE ,               
    PARSE_ATTR_ISSUER_CN_OID_STATE ,       
    PARSE_ATTR_ISSUER_CN_STATE ,        
    PARSE_ATTR_VALIDITY_STATE ,    
    PARSE_ATTR_VALIDITY_NOTBEFORE_STATE ,    
    PARSE_ATTR_VALIDITY_NOTAFTER_STATE ,     
    PARSE_ATTR_SUBJECT_CN_OID_STATE ,       
    PARSE_ATTR_SUBJECT_CN_STATE ,            
    PARSE_ATTR_SUBJPUBKEY_ALGO_STATE,    
    PARSE_ATTR_SUBJPUBKEY_KEY_STATE,    
    PARSE_ATTR_SUBJPUBKEY_EXPONENT_STATE,    
    PARSE_ATTR_SIGINFO_STATE ,   
    PARSE_ATTR_SIGINFO_ALGO_OID_STATE ,     
    PARSE_ATTR_SIGINFO_VALUE_STATE,
    PARSE_ATTR_COMPLETE
} PARSE_ATTR_STATE; 

typedef struct {
    u1 class;
    u1 encoding_form;
    u1 tag_num;
    u1 tag;
    u4 length;
    u1 *attrBuffer;
} tlv_info_t;


typedef struct {
    u4 length;
    u1 *readPtr;
    u1 *data;
} X509_Cert_t;

typedef struct {
    u1 version;
    u1 sn_length;
    u1 *sn;
    u1 sigAlgo_length;
    u1 *sigAlgo;
    u1 issuer_cn_length;
    u1 *issuer_cn;
    u1 validityNotBefore_length;
    u1 *validityNotBefore;
    u1 validityNotAfter_length;
    u1 *validityNotAfter;
    u1 subject_cn_length;
    u1 *subject_cn;
    u4 publicKey_length;
    u1 *publicKey;
    u4 publicKeyExp_length;
    u4 publicKeyExp;
    u4 signatureInfoValue_length;
    u1 *signatureInfoValue;
} X509_Cert_Attributes_t;

tlv_info_t tlvInfo;

X509_Cert_t *Certificate;

X509_Cert_Attributes_t Cert_Attributes;

u1 parse_result;

u1 parse_attribute_state;

u1 lengthBuffer[LENGTH_BUFFER_SIZE];

u1 issuer_subject_cn_oid[OID_ISSUER_SUBJECT_CN_SIZE] = OID_ISSUER_SUBJECT_CN;

u1 rsa_sha256_oid[OID_RSA_SHA256_SIZE] = OID_RSA_SHA256;

void x509_load( X509_Cert_t *cert );
void x509_parse_init( X509_Cert_t *cert);
void x509_parse( void );



#endif