/**
*	@file ssl.cpp
*	SSL connection routines using Schannel
*	@author Twilight
*	80% copied from FFmpeg implementation (tls_schannel.c),
*	used under GPLv2.0+ / LGPLv2.1+ license.
*/

#ifndef _SSL_H
#define _SSL_H

#include <Windows.h>
#include <security.h>
#include <Sspi.h>
#include <schannel.h>

struct SSL_CONTEXT
{
	SOCKET sock;
	char* ServerName;
	DWORD dwFlags;
	CredHandle Credential;
	TimeStamp Expiry;
	CtxtHandle Context;
	ULONG ulContextAttr;
	TimeStamp ContextExpiry;
	char* EncodedBuffer;
	char* DecodedBuffer;
	DWORD cbEncodedBuffer;
	DWORD cbDecodedBuffer;
	DWORD dwEncodedOffset;
	DWORD dwDecodedOffset;
	bool bConnectionClosed;
	bool bSSLCloseNotify;
	bool bIsConnected;
	SecPkgContext_StreamSizes Sizes;
};

/**
 *	Establish a new SSL connection.
 *	@param sock TCP socket to use. The socket must already be connected.
 *	@param server Server host name, used for certificate validation and SNI.
 *	@param context SSL context structure, should be zeroed before calling this function.
 *	@param verify If true, validate the server certificate.
 *	@return 1 if successful, 2 if certificate verification failed, 0 on any other failure
 */
DWORD SSLConnect(SOCKET sock, const char* server, SSL_CONTEXT* context, bool verify);

/**
 *	Read data from an SSL connection.
 *	@param context SSL context to read from
 *	@param buf Buffer to read into
 *	@param len Length of buf in bytes
 *	@return The number of bytes read, zero if connection closed, negative on error
 */
int SSLRead(SSL_CONTEXT* context, char* buf, int len);

/**
 *	Write data to an SSL connection.
 *	@param context SSL context to write to
 *	@param buf Buffer containing the data to write
 *	@paral len Size of the data in bytes
 *	@return The number of bytes written, zero if connection closed, negative on error
 */
int SSLWrite(SSL_CONTEXT* context, char* buf, int len);

/**
 *	Close an SSL connection.
 *	@param context SSL context to close
 *	@note This also closes the TCP connection.
 */
void SSLClose(SSL_CONTEXT* context);

#endif
