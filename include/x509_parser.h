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

#define MAX_CERTIFICATES    1

/**
 * @brief DER Encoding of ASN.1 Types
 * 
 */

/**
 * @brief Definitions for DER Encoding of ASN.1 Types
 * 
 */
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
#define TAG_BMPSTRING               (u1)0x1E
#define TAG_SEQUENCE                (u1)0x30
#define TAG_SET                     (u1)0x31
#define TAG_CHOICE                  (u1)0x82

#define TAG_IMPLICIT_PRIMITIVE      (u1)0x80
#define TAG_IMPLICIT_CONSTRUCTIVE   (u1)0xA0

#define CLASS_UNIVERSAL             (u1)0b00
#define CLASS_APPLICATION           (u1)0b01
#define CLASS_CONTEXT_SPECIFIC      (u1)0b10
#define CLASS_PRIVATE               (u1)0b11

#define BYTE_MASK_1BIT              (u1)0b1
#define BYTE_MASK_2BITS             (u1)0b11
#define BYTE_MASK_5BITS             (u1)0b11111

#define ENCODING_FORM_BIT_POS       5
#define ENCODING_FORM_BIT_MASK      (u1)( BYTE_MASK_1BIT<<ENCODING_FORM_BIT_POS )

#define CLASS_BITS_POS              6
#define CLASS_BITS_MASK             (u1)( BYTE_MASK_2BITS<<CLASS_BITS_POS )

#define LENGTH_EXTENDED_BIT_POS     7
#define LENGTH_EXTENDED_BIT_MASK    (u1)( BYTE_MASK_1BIT<<LENGTH_EXTENDED_BIT_POS )

#define PARSE_SUCCESS                       1
#define PARSE_FAIL                          0

#define PARSE_FORMAT_ERR                    1
#define PARSE_SERIAL_ERR                    2
#define PARSE_ISSUER_ERR                    3
#define PARSE_VALIDITY_ERR                  4
#define PARSE_SUBJECT_ERR                   5
#define PARSE_SIGNATURE_ERR                 6

typedef enum {
    PARSE_TLV_TAG_STATE,
    PARSE_TLV_LENGTH_STATE,
    PARSE_TLV_LENGTH_EXT_STATE,
    PARSE_TLV_CONTENT_STATE
} PARSE_TLV_STATE;

typedef enum {
    PARSE_ATTR_VERSION_STATE ,           
    PARSE_ATTR_SERIAL_STATE,             
    PARSE_ATTR_SIGALGO_STATE ,           
    PARSE_ATTR_ISSUER_STATE ,            
    PARSE_ATTR_VALIDITY_UTCTIME_STATE ,  
    PARSE_ATTR_VALIDITY_GENTIME_STATE  , 
    PARSE_ATTR_SUBJECT_STATE ,          
    PARSE_ATTR_SUBJPUBKEY_ALGO_STATE,    
    PARSE_ATTR_SUBJPUBKEY_KEY_STATE,    
    PARSE_ATTR_SIGINFO_ALGO_STATE ,     
    PARSE_ATTR_SIGINFO_VALUE_STATE  
} PARSE_ATTR_STATE; 

typedef struct {
    u1 encoding_form;
    u1 tag;
    u2 length;
    u1 *attrBuffer;
} tlv_info_t;


typedef struct {
    u2 length;
    u1 *readPtr;
    u1 *data;
} X509_Cert_t;

tlv_info_t tlvInfo;

X509_Cert_t *Certificate;

u1 parse_result;

u1 parse_tlv_state;

u1 parse_attribute_state;

void x509_load( X509_Cert_t *cert );
void x509_parse_init( X509_Cert_t *cert);
void x509_parse( u1 read );
void x509_parse_tag( u1 read );
void x509_parse_length( u1 read );
void x509_parse_content( u1 read );
void x509_parse_attr_version( u1 read );
void x509_parse_attr_serial( u1 read );
void x509_parse_attr_sigAlgo( u1 read );
void x509_parse_attr_issuer( u1 read );
void x509_parse_attr_validity( u1 read );
void x509_parse_attr_subject( u1 read );
void x509_parse_attr_subjPubKey_algo( u1 read );
void x509_parse_attr_subjPubKey_key( u1 read );
void x509_parse_attr_sigInfo_algo( u1 read );
void x509_parse_attr_sigInfo_value( u1 read );


#endif