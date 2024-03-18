#include "../include/x509_parser.h"
#include "../include/verification.h"
#include <stdio.h>

#define DER_CERT_BUFF_SIZE  1028
char filePath[] = "../sampleCert.der";


int main ( void )
{
    u1 cert_data[DER_CERT_BUFF_SIZE] = { 0 };
    u4 cert_fileSize;
    u4 freadResult;
    BOOL read_complete;
    X509_Cert_t Certificate;
    X509_Cert_Attributes_t* parsed_attr;
    FILE *der_cert;

    der_cert = fopen(filePath,"rb");  // r for read, b for binary

    if( der_cert == NULL )
    {
        printf("Can't open the file! path: %s\n", filePath );
    }

    /*get file size*/
    fseek( der_cert, 0, SEEK_END );
    cert_fileSize = (u4)ftell( der_cert );

    fseek( der_cert, 0, SEEK_SET );
    freadResult = fread(cert_data,sizeof(u1),cert_fileSize,der_cert);
    if( 0 != freadResult && cert_fileSize ==  freadResult ) // read 10 bytes to our buffer
    {
        read_complete = TRUE;
    }
    else{
        read_complete = FALSE;
    }

    if( read_complete )
    {
        Certificate.length = cert_fileSize;
        Certificate.data = cert_data;
        Certificate.readPtr = Certificate.data;
        x509_parse_init( &Certificate );
        if( PASS == x509_parse() )
        {
            parsed_attr = x509_getCertAttributes();
            printf("successfully parsed data!\n");
        }
        else{
            printf("parsing failed!\n");
        }
    }
    return 0;
}