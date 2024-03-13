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