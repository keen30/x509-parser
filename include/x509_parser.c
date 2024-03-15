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

u1 extendedLengthIndex;
u1 extendedLengthByteSize;

void x509_load( X509_Cert_t *cert );
void moveDataPtrToEndOfAttribute( u4 offset );


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

        Certificate->readPtr++;

        if( PARSE_TLV_CONTENT_STATE == parse_tlv_state )
        {
            if( ENCODING_FORM_PRIMITIVE == tlvInfo.encoding_form )
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
                parse_tlv_state = PARSE_TLV_TAG_STATE;
            }
        }
    }

}

void moveDataPtrToEndOfAttribute( u4 offset )
{
    Certificate->readPtr += offset;
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
    else
    {

    }
}

void x509_parse_length( u1 read )
{
    if( PARSE_TLV_LENGTH_STATE == parse_tlv_state )
    {
        u1 isLengthExtended = ( read&LENGTH_EXTENDED_BIT_MASK )>>LENGTH_EXTENDED_BIT_POS;
        u1 length_basic = read&LENGTH_BASIC_MASK;
        if( 0 != length_basic && LENGTH_BUFFER_SIZE >= length_basic )   /*check if the length value is greater than 0 or the buffer for
                                                                         extended length does not exceed LENGTH_BUFFER_SIZE*/
        {
            if( LENGTH_EXTENDED_TRUE == isLengthExtended )              /*check if extended length*/
            {
                extendedLengthByteSize = length_basic;                  /*length octet interpret the basic length value as byte size of extended length*/
                extendedLengthIndex = extendedLengthByteSize;  
                tlvInfo.length = 0xFFFFFFFF;                      
                parse_tlv_state = PARSE_TLV_LENGTH_EXT_STATE;
            }
            else{
                tlvInfo.length = length_basic;  
                parse_tlv_state = PARSE_TLV_LENGTH_EXT_STATE;
            }
        }
        else if ( 0 == length_basic) 
        {
            parse_tlv_state = PARSE_TLV_TAG_STATE;                      /*go back to TAG STATE if length is zero*/
        }
        else
        {
            parse_tlv_state = PARSE_TLV_ABNORMAL_STATE;
        }
    }
    else if( PARSE_TLV_LENGTH_EXT_STATE == parse_tlv_state )
    {
        u1 isLastByte = ( read&0x80 )>>7;                               /*read most significant bit*/
        u4 length_extended = read&LENGTH_BASIC_MASK;
        if( (u1)0 < extendedLengthIndex || (u1)1 == isLastByte )
        { 
            tlvInfo.length &= ( (u4)read )<<(extendedLengthIndex-1);
        }
        else{ 
            parse_tlv_state = PARSE_TLV_CONTENT_STATE;
        }
        extendedLengthIndex--;
    }
    else
    {

    }
}

void x509_parse_content( u1 read )
{
    if( PARSE_TLV_CONTENT_STATE == parse_tlv_state )
    {

    }
};

void x509_parse_attr_version( void )
{
    if( TAG_INTEGER == tlvInfo.tag )
    {
        Cert_Attributes.version = Certificate->readPtr;
    }
}

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