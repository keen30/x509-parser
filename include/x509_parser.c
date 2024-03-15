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

/**
 * @brief 
 * 
 */

#define ISSUER_READ_UNDEFINED       0
#define ISSUER_READ_C               1
#define ISSUER_READ_O               2
#define ISSUER_READ_CN              3

#define SUBJECT_READ_UNDEFINED      0
#define SUBJECT_READ_C              1
#define SUBJECT_READ_O              2
#define SUBJECT_READ_CN             3

u1 issuer_read_type;
u1 subject_read_type;

u1 extendedLengthIndex;
u1 extendedLengthByteSize;

void moveDataPtrToEndOfAttribute( u4 offset )
{
    Certificate->readPtr += offset;                                 /*Move the data pointer to end of attribute*/
}

u1 oid_checker( u1 *oid_dataPtr, u1 *oid_compare, u4 length)
{
    u1 *oid_1 = oid_dataPtr;
    u1 *oid_2 = oid_compare;
    u1 index = 0;
    u1 result = PASS;

    while( index < length )
    {
        if( *oid_1 != *oid_2 )
        {
            result = FAIL;
            break;
        }
    }
    
    return result;
}

void x509_load( X509_Cert_t *cert );
void moveDataPtrToEndOfAttribute( u4 offset );
void x509_parse_init( X509_Cert_t *cert )
{
    Certificate = cert;
    issuer_read_type = ISSUER_READ_UNDEFINED;
    issuer_read_type = SUBJECT_READ_UNDEFINED;
}

void x509_parse( void )
{
    u1 dataPtr_idx = 0;
    Certificate->readPtr = Certificate->data;

    while ( Certificate->length > dataPtr_idx )
    {
        u1 data = *( Certificate->readPtr );

        switch (parse_tlv_state)
        {
            case PARSE_TLV_TAG_STATE:
                x509_parse_tag( data );
                break;
            case PARSE_TLV_LENGTH_STATE:
                x509_parse_length( data );
                break;
            case PARSE_TLV_LENGTH_EXT_STATE:
                x509_parse_length_extended( data );
                break;
            case PARSE_TLV_CONTENT_STATE:
                x509_parse_content( data );
                break;
            
            default:
                parse_tlv_state = PARSE_TLV_ABNORMAL_STATE;
                break;
        }
        
        Certificate->readPtr++;

        if( ENCODING_FORM_PRIMITIVE == tlvInfo.encoding_form )
        {
            switch (parse_attribute_state)
            {
            case /* constant-expression */:
                /* code */
                break;
            
            default:
                break;
            }
            x509_parse_block_cert();
            x509_parse_block_tbsCert();
            x509_parse_block_versionExplicit();
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

            moveDataPtrToEndOfAttribute( tlvInfo.length );
            parse_tlv_state = PARSE_TLV_TAG_STATE;
        }
        else if( ENCODING_FORM_CONSTRUCTIVE == tlvInfo.encoding_form )
        {

        }
        else {
            parse_tlv_state = PARSE_TLV_ABNORMAL_STATE;
        }

        /*process abnormal state start here*/
        /*process abnormal state end here*/

    }

}

void x509_parse_tag( u1 read )
{
    tlvInfo.class = ( read&CLASS_BITS_MASK )>>CLASS_BITS_POS;
    tlvInfo.encoding_form = ( read&ENCODING_FORM_BIT_MASK )>>ENCODING_FORM_BIT_POS;
    tlvInfo.tag = read&TAG_NUMBER_MASK;
    tlvInfo.attrBuffer = NULL;
    tlvInfo.length = 0;
    tlvInfo.readContentState = PARSE_READCONTENT_IDLE;
    parse_tlv_state = PARSE_TLV_LENGTH_STATE;
}

void x509_parse_length( u1 read )
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

void x509_parse_length_extended( u1 read )
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

void x509_parse_content( u1 read )
{
    u1 tag_val = read&0x3F;
    u1 class_val = ( read&CLASS_BITS_MASK )>>CLASS_BITS_POS;
    switch (read)
    {

    case TAG_TELETEXSTRING:
    case TAG_BMPSTRING:
    case TAG_UTF8STRING:
    case TAG_PRINTABLESTRING:
    case TAG_IA5STRING:
    case TAG_OCTETSTRING:
    case TAG_UNIVERSALSTRING:
    case TAG_BOOLEAN:
    case TAG_INTEGER:
    case TAG_OBJECTIDENTIFIER:
        Certificate->readPtr--;                     /*If it's a value, move back the data pointer a byte*/          
        break;
    
    case TAG_BITSTRING:
                                                    /*If it's a bitstring tag, the first byte of content is the unused bits value*/    
        break;
        

    default:
        Certificate->readPtr--;                     /*If it's unknown tag, move back the data pointer a byte*/     
        break;
    }
};

void x509_parse_block_cert( void );
void x509_parse_block_tbsCert( void );
void x509_parse_block_versionExplicit( void );

void x509_parse_attr_version( void )
{
    if( PARSE_READCONTENT_READING == tlvInfo.readContentState && TAG_INTEGER == tlvInfo.tag )
    {
        Cert_Attributes.version = *( Certificate->readPtr );
        tlvInfo.readContentState = PARSE_READCONTENT_COMPLETE;
    }
}

void x509_parse_attr_serial( void )
{
    if( PARSE_READCONTENT_READING == tlvInfo.readContentState && TAG_INTEGER == tlvInfo.tag )
    {
        Cert_Attributes.sn_length = tlvInfo.length;
        Cert_Attributes.sn = *( Certificate->readPtr );
        tlvInfo.readContentState = PARSE_READCONTENT_COMPLETE;
    }
}


void x509_parse_attr_sigAlgo_oid( void )
{
    if( PARSE_READCONTENT_READING == tlvInfo.readContentState && TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        Cert_Attributes.sigAlgo_length = tlvInfo.length;
        Cert_Attributes.sigAlgo = *( Certificate->readPtr );
        tlvInfo.readContentState = PARSE_READCONTENT_COMPLETE;
    }
}

void x509_parse_attr_issuer_oid_cn( void )
{
    if( PARSE_READCONTENT_READING == tlvInfo.readContentState && TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        u1 *oid = *( Certificate->readPtr );
        if( PASS == oid_checker( issuer_subject_cn_oid, oid, tlvInfo.length ) )
        {
            issuer_read_type = ISSUER_READ_CN;
            tlvInfo.readContentState = PARSE_READCONTENT_COMPLETE;
        }
    }
}

void x509_parse_attr_issuer_cn( void )
{
    if( PARSE_READCONTENT_READING == tlvInfo.readContentState && ISSUER_READ_CN == issuer_read_type &&
        (
            TAG_TELETEXSTRING == tlvInfo.tag ||                             /*Described in RFC 5280 */
            TAG_PRINTABLESTRING == tlvInfo.tag ||
            TAG_UNIVERSALSTRING == tlvInfo.tag ||
            TAG_UTF8STRING == tlvInfo.tag ||
            TAG_BMPSTRING == tlvInfo.tag 
        )
    )
    {
        Cert_Attributes.issuer_cn_length = tlvInfo.length;
        Cert_Attributes.issuer_cn = *( Certificate->readPtr );
        tlvInfo.readContentState = PARSE_READCONTENT_COMPLETE;
    }
}

void x509_parse_attr_validityNotBefore( void );
void x509_parse_attr_validityNotAfter( void );
void x509_parse_attr_subject_oid_cn( void );
void x509_parse_attr_subject_cn( void );
void x509_parse_attr_subjPubKey_algo_oid( void );
void x509_parse_attr_subjPubKey_key( void );
void x509_parse_attr_subjPubKey_keyExp( void );
void x509_parse_block_sigInfo( void );
void x509_parse_attr_sigInfo_algo_oid( void );
void x509_parse_attr_sigInfo_value( void );