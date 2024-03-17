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

void x509_parse_tag( void );
void x509_parse_length( void );
void x509_parse_length_extended( void );
void x509_parse_content( void );

void x509_parse_block_cert( void );
void x509_parse_block_tbsCert( void );
void x509_parse_block_versionExplicit( void );
void x509_parse_attr_version( void );
void x509_parse_attr_serial( void );
void x509_parse_attr_sigAlgo_oid( void );
void x509_parse_attr_issuer_oid_c( void );
void x509_parse_attr_issuer_oid_o( void );
void x509_parse_attr_issuer_oid_cn( void );
void x509_parse_attr_issuer_cn( void );
void x509_parse_attr_validityNotBefore_UTCtime( void );
void x509_parse_attr_validityNotAfter_UTCtime( void );
void x509_parse_attr_subject_oid_c( void );
void x509_parse_attr_subject_oid_o( void );
void x509_parse_attr_subject_oid_cn( void );
void x509_parse_attr_subject_cn( void );
void x509_parse_attr_subjPubKey_algo_oid( void );
void x509_parse_attr_subjPubKey_key( void );
void x509_parse_attr_subjPubKey_keyExp( void );
void x509_parse_block_sigInfo( void );
void x509_parse_attr_sigInfo_algo_oid( void );
void x509_parse_attr_sigInfo_value( void );

u1 dataPtr_Index;
u1 *dataPtr_endOfAttribute;
u1 bitString_unused_bits;

__attribute__((always_inline)) static inline u1 dataPtr( void )                     /*reads the data but doesn't move the data pointer*/
{
    return Certificate->readPtr;
}

__attribute__((always_inline)) static inline u1 data_peek( void )                     /*reads the data but doesn't move the data pointer*/
{
    return *( Certificate->readPtr);
}

__attribute__((always_inline)) static inline void dataPtr_increment( void )
{
    Certificate->readPtr++;
    dataPtr_Index++;
}

__attribute__((always_inline)) static inline void dataPtr_deccrement( void )
{
    Certificate->readPtr--;
    dataPtr_Index--;
}
__attribute__((always_inline)) static inline void dataPtr_offset( u4 offset )
{
    Certificate->readPtr += offset;
    dataPtr_Index += offset;
}

__attribute__((always_inline)) static inline void moveDataPtrToEndOfAttribute( void )
{
    Certificate->readPtr = dataPtr_endOfAttribute;                                      /*Move the data pointer to end of attribute*/
}
__attribute__((always_inline)) static inline u1 data_read( void )                     /*reads 1 byte of data and increment data pointer*/
{
    u1 data = *( Certificate->readPtr);
    dataPtr_increment();
    return ;
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
void x509_parse_init( X509_Cert_t *cert )
{
    Certificate = cert;
    Certificate->readPtr = Certificate->data;
    dataPtr_Index = 0;
    parse_attribute_state = PARSE_ATTR_CERT_STATE;
}

void x509_parse( void )
{
    while ( Certificate->length > dataPtr_Index )
    {
        x509_parse_tag();
        x509_parse_length();
        x509_parse_length_extended();
        x509_parse_content();

        switch (parse_attribute_state)
        {
            case PARSE_ATTR_CERT_STATE:
                x509_parse_block_cert();
                break;
            case PARSE_ATTR_TBSCERT_STATE:
                x509_parse_block_tbsCert();
                break;
            case PARSE_ATTR_VERSION_EXPLICIT_STATE:
                x509_parse_block_versionExplicit();
                break;
            case PARSE_ATTR_VERSION_STATE:
                x509_parse_attr_version();
                break;
            case PARSE_ATTR_SERIAL_STATE:
                x509_parse_attr_serial();
                break;
            case PARSE_ATTR_SIGALGO_OID_STATE:
                x509_parse_attr_sigAlgo_oid();
                break;
            case PARSE_ATTR_ISSUER_CN_OID_STATE:
                x509_parse_attr_issuer_oid_cn();
                break;
            case PARSE_ATTR_ISSUER_CN_STATE:
                x509_parse_attr_issuer_cn();
                break;
            case PARSE_ATTR_VALIDITY_NOTBEFORE_STATE:
                x509_parse_attr_validityNotBefore();
                break;
            case PARSE_ATTR_VALIDITY_NOTAFTER_STATE:
                x509_parse_attr_validityNotAfter();
                break;
            case PARSE_ATTR_SUBJECT_CN_OID_STATE:
                x509_parse_attr_subject_oid_cn();
                break;
            case PARSE_ATTR_SUBJECT_CN_STATE:
                x509_parse_attr_subject_cn();
                break;
            case PARSE_ATTR_SUBJPUBKEY_ALGO_STATE:
                x509_parse_attr_subjPubKey_algo_oid();
                break;
            case PARSE_ATTR_SUBJPUBKEY_KEY_STATE:
                x509_parse_attr_subjPubKey_key();
                break;
            case PARSE_ATTR_SUBJPUBKEY_EXPONENT_STATE:
                x509_parse_attr_subjPubKey_keyExp();
                break;
            case PARSE_ATTR_SIGINFO_STATE:
                x509_parse_block_sigInfo();
                break;
            case PARSE_ATTR_SIGINFO_ALGO_OID_STATE:
                x509_parse_attr_sigAlgo_oid();
                break;
            case PARSE_ATTR_SIGINFO_VALUE_STATE:
                x509_parse_attr_sigInfo_value();
                break;
            case PARSE_ATTR_COMPLETE:
                break;
            
            default:
                break;
        }

        if( ENCODING_FORM_PRIMITIVE == tlvInfo.encoding_form )          /* move to end of attribute content*/
        {
            moveDataPtrToEndOfAttribute();
        }

    }

    /*process abnormal state start here*/
    /*process abnormal state end here*/

}

void x509_parse_tag()
{
    u1 read = dataPtr_read();
    tlvInfo.class = ( read&CLASS_BITS_MASK )>>CLASS_BITS_POS;
    tlvInfo.encoding_form = ( read&ENCODING_FORM_BIT_MASK )>>ENCODING_FORM_BIT_POS;
    tlvInfo.tag_num = read&TAG_NUMBER_MASK;
    tlvInfo.tag = read;
    tlvInfo.length = 0;
    tlvInfo.attrBuffer = NULL;
    bitString_unused_bits = 0;
}

void x509_parse_length()
{
    u1 read = dataPtr_read();
    u1 isLengthExtended = ( read&LENGTH_EXTENDED_BIT_MASK )>>LENGTH_EXTENDED_BIT_POS;
    u1 length_basic = read&LENGTH_BASIC_MASK;
    if( 0 != length_basic )                                                                     /*check if the length value is greater than 0 */                                     
    {
        if( LENGTH_EXTENDED_TRUE == isLengthExtended && LENGTH_BUFFER_SIZE >= length_basic )    /*check if extended length*/
        {                                                                                       /*extended length should not exceed LENGTH_BUFFER_SIZE*/
            tlvInfo.length = length_basic;                                                      /*for extended length, this value is the extended length byte size*/
        }
        else{                                                                                   /*for basic length, only 1 byte */
            tlvInfo.length = length_basic;  
        }
    }
    else
    {
    }
}

void x509_parse_length_extended()
{
    u1 extendedLengthByteSize = tlvInfo.length;  
    u1 K = extendedLengthByteSize;                              /*inialize to most significant byte. the byte sequence is big endian*/
    u1 leading_byte = dataPtr_read()&LENGTH_BASIC_MASK;         /*only get the significant bits = bit6 to bit0 for leading byte */
    
    tlvInfo.length = ( ((u4)0u) & ((u4)leading_byte)<<(8*(K-1)) );  /*save the leading byte value*/
    K--;

    while( 0 < K )                                              /*loop extended length bytes*/
    {
        tlvInfo.length |= ((u4)dataPtr_read())<<( 8*(K-1) );
        K--;
    }

    
    dataPtr_endOfAttribute = dataPtr();
    dataPtr_endOfAttribute += tlvInfo.length;                   /*gets the pointer to next tag*/
}


void x509_parse_content()
{
    u1 data = data_peek();
    switch (data)
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
            break;
        
        case TAG_BITSTRING:
            bitString_unused_bits = dataPtr_read();             /*If it's a bitstring tag, the first byte of content is the unused bits value. so move the */    
            break;
            
        case TAG_SEQUENCE:
        case TAG_SET:        
            break;
            
        default:    
            break;
    }
};

void x509_parse_block_cert( void )
{
    if( TAG_SEQUENCE == tlvInfo.tag )
    {
        parse_attribute_state = PARSE_ATTR_TBSCERT_STATE;
    }
}

void x509_parse_block_tbsCert( void )
{
    if( TAG_SEQUENCE  == tlvInfo.tag )
    {
        parse_attribute_state = PARSE_ATTR_VERSION_EXPLICIT_STATE;
    }
}

void x509_parse_block_versionExplicit( void )
{
    if( TAG_CHOICE(4)  == tlvInfo.tag )
    {
        parse_attribute_state = PARSE_ATTR_VERSION_STATE;
    }
}

void x509_parse_attr_version( void )
{
    if( TAG_INTEGER == tlvInfo.tag )
    {
        Cert_Attributes.version = data_peek();                /*reads the certificate version*/
        parse_attribute_state = PARSE_ATTR_SERIAL_STATE;
    }
}

void x509_parse_attr_serial( void )
{
    if( TAG_INTEGER == tlvInfo.tag )
    {
        Cert_Attributes.sn_length = tlvInfo.length;
        Cert_Attributes.sn = dataPtr();
        parse_attribute_state = PARSE_ATTR_SIGALGO_OID_STATE;
    }
}

void x509_parse_attr_sigAlgo_oid( void )
{
    if( TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        Cert_Attributes.sigAlgo_length = tlvInfo.length;
        Cert_Attributes.sigAlgo = dataPtr();
        parse_attribute_state = PARSE_ATTR_ISSUER_CN_OID_STATE;
    }
}

void x509_parse_attr_issuer_oid_cn( void )
{
    if( TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        u1 *oid = dataPtr();
        if( PASS == oid_checker( issuer_subject_cn_oid, oid, tlvInfo.length ) )
        {
            parse_attribute_state = PARSE_ATTR_ISSUER_CN_STATE;
        }
    }
}

void x509_parse_attr_issuer_cn( void )
{
    if(  
        TAG_TELETEXSTRING == tlvInfo.tag ||                             /*Described in RFC 5280 */
        TAG_PRINTABLESTRING == tlvInfo.tag ||
        TAG_UNIVERSALSTRING == tlvInfo.tag ||
        TAG_UTF8STRING == tlvInfo.tag ||
        TAG_BMPSTRING == tlvInfo.tag 
        )
    {
        Cert_Attributes.issuer_cn_length = tlvInfo.length;
        Cert_Attributes.issuer_cn = dataPtr();
        parse_attribute_state = PARSE_ATTR_VALIDITY_NOTBEFORE_STATE;
    }
}

void x509_parse_attr_validityNotBefore_UTCtime( void )
{
    if( TAG_UTCTIME == tlvInfo.tag )
    {
        Cert_Attributes.validityNotBefore_length = tlvInfo.length;
        Cert_Attributes.validityNotBefore = dataPtr();
        parse_attribute_state = PARSE_ATTR_VALIDITY_NOTAFTER_STATE;
    }
}
void x509_parse_attr_validityNotAfter_UTCtime( void )
{
    if( TAG_UTCTIME == tlvInfo.tag )
    {
        Cert_Attributes.validityNotAfter_length = tlvInfo.length;
        Cert_Attributes.validityNotAfter = dataPtr();
        parse_attribute_state = PARSE_ATTR_SUBJECT_CN_OID_STATE;
    }
}

void x509_parse_attr_subject_oid_cn( void )
{
    if( TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        u1 *oid = dataPtr();
        if( PASS == oid_checker( issuer_subject_cn_oid, oid, tlvInfo.length ) )
        {
            parse_attribute_state = PARSE_ATTR_SUBJECT_CN_STATE;
        }
    }
}

void x509_parse_attr_subject_cn( void )
{
    if(  
        TAG_TELETEXSTRING == tlvInfo.tag ||                             /*Described in RFC 5280 */
        TAG_PRINTABLESTRING == tlvInfo.tag ||
        TAG_UNIVERSALSTRING == tlvInfo.tag ||
        TAG_UTF8STRING == tlvInfo.tag ||
        TAG_BMPSTRING == tlvInfo.tag 
        )
    {
        Cert_Attributes.subject_cn_length = tlvInfo.length;
        Cert_Attributes.subject_cn = dataPtr();
        parse_attribute_state = PARSE_ATTR_SUBJPUBKEY_ALGO_STATE;
    }
}

void x509_parse_attr_subjPubKey_algo_oid( void )
{
    if( TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        u1 *oid = dataPtr();
        if( PASS == oid_checker( rsa_sha256_oid, oid, tlvInfo.length ) )
        {
            parse_attribute_state = PARSE_ATTR_SUBJPUBKEY_KEY_STATE;
        }
    }
}

void x509_parse_attr_subjPubKey_key( void )
{
    if( TAG_BITSTRING == tlvInfo.tag && 0 == bitString_unused_bits )
    {
        Cert_Attributes.publicKey_length = tlvInfo.length - 1;
        Cert_Attributes.publicKey = dataPtr();
        parse_attribute_state = PARSE_ATTR_SUBJPUBKEY_EXPONENT_STATE;
    }
}

void x509_parse_attr_subjPubKey_keyExp( void )
{
    if( TAG_INTEGER == tlvInfo.tag )
    {    
        u1 M = tlvInfo.length;
        u4 public_exponent = 0u;

        while( 0 < M )                                              /*loop integer bytes*/
        {
            public_exponent |= dataPtr_read()<<( 8*(M-1) );
            M--;
        }

        Cert_Attributes.publicKeyExp = public_exponent;
        parse_attribute_state = PARSE_ATTR_SIGINFO_STATE;
    }
}

void x509_parse_block_sigInfo( void )
{
    if( TAG_SEQUENCE == tlvInfo.tag )
    {
        parse_attribute_state = PARSE_ATTR_SIGINFO_ALGO_OID_STATE;
    }
}

void x509_parse_attr_sigInfo_algo_oid( void )
{
    if( TAG_OBJECTIDENTIFIER == tlvInfo.tag )
    {
        u1 *oid = dataPtr();
        if( PASS == oid_checker( rsa_sha256_oid, oid, tlvInfo.length ) )
        {
            parse_attribute_state = PARSE_ATTR_SIGINFO_VALUE_STATE;
        }
    }
}

void x509_parse_attr_sigInfo_value( void )
{
    if( TAG_BITSTRING == tlvInfo.tag && 0 == bitString_unused_bits )
    {
        Cert_Attributes.signatureInfoValue_length = tlvInfo.length;
        Cert_Attributes.signatureInfoValue = dataPtr();
        parse_attribute_state = PARSE_ATTR_COMPLETE;
    }
}