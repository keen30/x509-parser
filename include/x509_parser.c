/**
 * @file x509_parser.c
 * @author LeandroKeenZapa
 * @brief 
 * @version 0.1
 * @date 2024-03-09
 * 
 * @copyright Copyright (c) 2024
 * 
 */


#include "x509_parser.h"

void x509_load( X509_Cert_t *cert );
void x509_parse_init( X509_Cert_t *cert )
{
    Certificate = cert;
}

void x509_parse( void )
{
    u1 dataPtr_idx = 0;
    Certificate->readPtr = Certificate->data;
    while ( Certificate->length > dataPtr_idx )
    {
        u1 data = *( Certificate->readPtr );
        x509_parse_tag( data );
        x509_parse_length( data );
        x509_parse_content( data );

        if( PARSE_READCONTENT_COMPLETE == tlvInfo.readContentState )
        {
            x509_parse_attr_version();
            x509_parse_attr_serial();
            x509_parse_attr_sigAlgo_oid();
            x509_parse_attr_issuer_oid_cn();
            x509_parse_attr_issuer_cn();
            x509_parse_attr_validityNotBefore();
            x509_parse_attr_validityNotAfter();
            x509_parse_attr_subject_oid_cn();
            x509_parse_attr_subject_cn();
            x509_parse_attr_subjPubKey_algo_oid();
            x509_parse_attr_subjPubKey_key();
            x509_parse_attr_subjPubKey_keyExp();
            x509_parse_attr_sigAlgo_oid();
            x509_parse_attr_sigInfo_algo_oid();
            x509_parse_attr_sigInfo_value();
        }

        Certificate->readPtr++;
    }

}

void x509_parse_tag( u1 read )
{
    if( PARSE_TLV_TAG_STATE == parse_tlv_state )
    {
        tlvInfo.class = ( read&CLASS_BITS_MASK )>>CLASS_BITS_POS;
        tlvInfo.encoding_form = ( read&ENCODING_FORM_BIT_MASK )>>ENCODING_FORM_BIT_POS;
        tlvInfo.tag = read&TAG_NUMBER_MASK;
        tlvInfo.attrBuffer = NULL;
        tlvInfo.length = 0;
        tlvInfo.readContentState = PARSE_READCONTENT_IDLE;
        parse_tlv_state = PARSE_TLV_LENGTH_STATE;
    }
}

void x509_parse_length( u1 read )
{
    if(PARSE_TLV_LENGTH_STATE)
    {
        u1 isLengthExtended = ( read&LENGTH_EXTENDED_BIT_MASK )>>LENGTH_EXTENDED_BIT_POS;
        if( LENGTH_EXTENDED_TRUE == isLengthExtended )
        {
            
        }
    }

}


void x509_parse_content( u1 read );
void x509_parse_attr_version( void );
void x509_parse_attr_serial( void );
void x509_parse_attr_sigAlgo_oid( void );
void x509_parse_attr_issuer_oid_cn( void );
void x509_parse_attr_issuer_cn( void );
void x509_parse_attr_validityNotBefore( void );
void x509_parse_attr_validityNotAfter( void );
void x509_parse_attr_subject_oid_cn( void );
void x509_parse_attr_subject_cn( void );
void x509_parse_attr_subjPubKey_algo_oid( void );
void x509_parse_attr_subjPubKey_key( void );
void x509_parse_attr_subjPubKey_keyExp( void );
void x509_parse_attr_sigInfo_algo_oid( void );
void x509_parse_attr_sigInfo_value( void );