/**
 *	@file ssl.cpp
 *	SSL connection routines using Schannel
 *	@author Twilight
 *	80% copied from FFmpeg implementation (tls_schannel.c),
 *	used under GPLv2.0+ / LGPLv2.1+ license.
 */

#include "ssl.h"

#ifndef UNISP_NAME_A
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"
#endif
#ifndef UNISP_NAME_W
#define UNISP_NAME_W L"Microsoft Unified Security Protocol Provider"
#endif
#ifndef UNISP_NAME
#ifdef UNICODE
#define UNISP_NAME  UNISP_NAME_W
#else
#define UNISP_NAME  UNISP_NAME_A
#endif
#endif

#define SCHANNEL_INITIAL_BUFFER_SIZE 4096
#define SCHANNEL_FREE_BUFFER_SIZE 1024

static void InitSecBuffer(SecBuffer *buffer, unsigned long BufType,
	void *BufDataPtr, unsigned long BufByteSize)
{
	buffer->cbBuffer = BufByteSize;
	buffer->BufferType = BufType;
	buffer->pvBuffer = BufDataPtr;
}

static void InitSecBufferDesc(SecBufferDesc *desc, SecBuffer *BufArr,
	unsigned long NumArrElem)
{
	desc->ulVersion = SECBUFFER_VERSION;
	desc->pBuffers = BufArr;
	desc->cBuffers = NumArrElem;
}

static DWORD SSLHandshake(SSL_CONTEXT* context, bool readfirst)
{
	int result = 0;
	SecBuffer outbuf[3];
	SecBufferDesc outbuf_desc;
	SecBuffer inbuf[2];
	SecBufferDesc inbuf_desc;
	bool read_data = readfirst;
	SECURITY_STATUS sspistat;

	if (context->EncodedBuffer == NULL) {
		context->EncodedBuffer = (char*)malloc(SCHANNEL_INITIAL_BUFFER_SIZE);
		if (context->EncodedBuffer == NULL) {
			return 0;
		}
		context->cbEncodedBuffer = SCHANNEL_INITIAL_BUFFER_SIZE;
	}
	if (context->DecodedBuffer == NULL) {
		context->DecodedBuffer = (char*)malloc(SCHANNEL_INITIAL_BUFFER_SIZE);
		if (context->DecodedBuffer == NULL) {
			free(context->EncodedBuffer);
			context->EncodedBuffer = NULL;
			context->cbEncodedBuffer = 0;
			return 0;
		}
		context->cbDecodedBuffer = SCHANNEL_INITIAL_BUFFER_SIZE;
	}
	// Handshake loop
	while (1) {
		if (read_data) {
			result = recv(context->sock, context->EncodedBuffer + context->dwEncodedOffset, context->cbEncodedBuffer - context->dwEncodedOffset, 0);
			if (result <= 0) {
				return 0;
			}
			context->dwEncodedOffset += result;
		}
		// Init security buffers
		InitSecBuffer(&inbuf[0], SECBUFFER_TOKEN, malloc(context->dwEncodedOffset), context->dwEncodedOffset);
		InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&inbuf_desc, inbuf, 2);
		InitSecBuffer(&outbuf[0], SECBUFFER_TOKEN, NULL, 0);
		InitSecBuffer(&outbuf[1], SECBUFFER_ALERT, NULL, 0);
		InitSecBuffer(&outbuf[2], SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&outbuf_desc, outbuf, 3);
		if (inbuf[0].pvBuffer == NULL) {
			return 0;
		}
		memcpy(inbuf[0].pvBuffer, context->EncodedBuffer, context->dwEncodedOffset);
		sspistat = InitializeSecurityContextA(&context->Credential, &context->Context, (SEC_CHAR*)context->ServerName,
			context->dwFlags, 0, 0, &inbuf_desc, 0, NULL, &outbuf_desc, &context->ulContextAttr, &context->ContextExpiry);
		free(inbuf[0].pvBuffer);
		if (sspistat == SEC_E_INCOMPLETE_MESSAGE) {
			// Not received entire message yet
			read_data = true;
			continue;
		}
		if (sspistat == SEC_E_INCOMPLETE_CREDENTIALS) {
			// Server requested client certificate, which we don't
			// support. Attempt to continue without one.
			read_data = false;
			continue;
		}
		if (sspistat != SEC_I_CONTINUE_NEEDED && sspistat != SEC_E_OK) {
			// Certificate validation failed (or another handshake error)
			if (outbuf[0].pvBuffer != NULL) FreeContextBuffer(outbuf[0].pvBuffer);
			if (outbuf[1].pvBuffer != NULL) FreeContextBuffer(outbuf[1].pvBuffer);
			if (outbuf[2].pvBuffer != NULL) FreeContextBuffer(outbuf[2].pvBuffer);
			// Special return code, in case we want to warn users.
			return 2;
		}
		for (int i = 0; i < 3; i++) {
			// Send handshake response if we have one
			if (outbuf[i].BufferType == SECBUFFER_TOKEN && outbuf[i].cbBuffer > 0) {
				result = send(context->sock, (const char*)outbuf[i].pvBuffer, outbuf[i].cbBuffer, 0);
				if (result <= 0 || (DWORD)result != outbuf[i].cbBuffer) {
					if (outbuf[0].pvBuffer != NULL) FreeContextBuffer(outbuf[0].pvBuffer);
					if (outbuf[1].pvBuffer != NULL) FreeContextBuffer(outbuf[1].pvBuffer);
					if (outbuf[2].pvBuffer != NULL) FreeContextBuffer(outbuf[2].pvBuffer);
					return 0;
				}
				if (outbuf[i].pvBuffer != NULL) {
					FreeContextBuffer(outbuf[i].pvBuffer);
					outbuf[i].pvBuffer = NULL;
				}
			}
		}
		if (inbuf[1].BufferType == SECBUFFER_EXTRA && inbuf[1].cbBuffer > 0) {
			// Extra data in buffer after handshake data, may be
			// part of the user payload or an additonal part of
			// the handshake
			if (context->dwEncodedOffset > inbuf[1].cbBuffer) {
				memmove(context->EncodedBuffer, (context->EncodedBuffer + context->dwEncodedOffset) - inbuf[1].cbBuffer, inbuf[1].cbBuffer);
				context->dwEncodedOffset = inbuf[1].cbBuffer;
				if (sspistat == SEC_I_CONTINUE_NEEDED) {
					read_data = false;
					continue;
				}
			}
		}
		else {
			context->dwEncodedOffset = 0;
		}
		if (sspistat == SEC_I_CONTINUE_NEEDED) {
			read_data = true;
			continue;
		}
		break;
	}
	return 1;
}

DWORD SSLConnect(SOCKET sock, const char* server, SSL_CONTEXT* context, bool verify)
{
	SecBuffer outbuf;
	SecBufferDesc outbuf_desc;

	if (!server || !context) {
		return 0;
	}
	size_t server_len = strlen(server);
	context->ServerName = (char*)malloc(server_len + 1);
	if (!context->ServerName) {
		return 0;
	}
	context->dwFlags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
	SCHANNEL_CRED SchCreds = { 0 };
	SchCreds.dwVersion = SCHANNEL_CRED_VERSION;
	if (verify) {
		SchCreds.dwFlags = (SCH_CRED_AUTO_CRED_VALIDATION | SCH_CRED_REVOCATION_CHECK_CHAIN);
	}
	else {
		SchCreds.dwFlags = (SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_IGNORE_NO_REVOCATION_CHECK | SCH_CRED_IGNORE_REVOCATION_OFFLINE);
	}
	strncpy(context->ServerName, server, server_len + 1);
	context->ServerName[server_len] = '\0';
	// Get initial handshake data
	SECURITY_STATUS sspistat = AcquireCredentialsHandleA(NULL,
		UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &SchCreds, NULL, NULL,
		&context->Credential, &context->Expiry);
	if (sspistat != SEC_E_OK) {
		free(context->ServerName);
		return 0;
	}
	InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
	InitSecBufferDesc(&outbuf_desc, &outbuf, 1);
	sspistat = InitializeSecurityContextA(&context->Credential, NULL, (SEC_CHAR*)server,
		context->dwFlags, 0, 0, NULL, 0, &context->Context, &outbuf_desc,
		&context->ulContextAttr, &context->ContextExpiry);
	if (sspistat != SEC_I_CONTINUE_NEEDED) {
		free(context->ServerName);
		return 0;
	}
	// Send initial handshake data to server
	int result = send(sock, (const char*)outbuf.pvBuffer, outbuf.cbBuffer, 0);
	if (result < 0 || (DWORD)result != outbuf.cbBuffer) {
		free(context->ServerName);
		return 0;
	}
	FreeContextBuffer(outbuf.pvBuffer);
	context->cbEncodedBuffer = 0;
	context->dwEncodedOffset = 0;
	context->cbDecodedBuffer = 0;
	context->dwDecodedOffset = 0;

	context->sock = sock;
	result = SSLHandshake(context, true);
	if (result != 1) {
		SSLClose(context);
		return result;
	}
	context->bIsConnected = true;

	return 1;
}

int SSLRead(SSL_CONTEXT* context, char* buf, int len)
{
	int ret = 0;
	DWORD size = 0;
	bool doagain = false;

	do {
		ret = 0;
		size = 0;
		DWORD requiredSize = len + SCHANNEL_FREE_BUFFER_SIZE;
		SECURITY_STATUS sspistat = SEC_E_OK;
		SecBuffer inbuf[4];
		SecBufferDesc inbuf_desc;
		doagain = false;

		if (context->dwDecodedOffset > 0) {
			// There's already decoded data available from a previous call
			// so just return it.
			goto cleanup;
		}
		if (context->bSSLCloseNotify) {
			// Server has indicated a shutdown, meaning there will be no
			// more incoming encrypted data, so just send any cached
			// data if we still have it.
			goto cleanup;
		}
		if (!context->bConnectionClosed) {
			// Make sure our buffer is big enough for the incoming data
			size = context->cbEncodedBuffer - context->dwEncodedOffset;
			if (size < SCHANNEL_FREE_BUFFER_SIZE || context->cbEncodedBuffer < requiredSize) {
				// Reallocate the buffer to accomodate for the required length
				context->cbEncodedBuffer = context->dwEncodedOffset + SCHANNEL_FREE_BUFFER_SIZE;
				if (context->cbEncodedBuffer < requiredSize) {
					context->cbEncodedBuffer = requiredSize;
				}
				char* pNewBuffer = (char*)realloc(context->EncodedBuffer, context->cbEncodedBuffer);
				if (!pNewBuffer) {
					ret = -1;
					goto cleanup;
				}
				context->EncodedBuffer = pNewBuffer;
			}
		}
		ret = recv(context->sock, context->EncodedBuffer + context->dwEncodedOffset, context->cbEncodedBuffer - context->dwEncodedOffset, 0);
		if (ret == 0) {
			context->bConnectionClosed = true;
			goto cleanup;
		}
		else if (ret < 0) {
			goto cleanup;
		}
		context->dwEncodedOffset += ret;

		while (sspistat == SEC_E_OK && context->dwEncodedOffset > 0) {
			// Buffer for the DecryptMessage call
			InitSecBuffer(&inbuf[0], SECBUFFER_DATA, context->EncodedBuffer, context->dwEncodedOffset);
			// Need 3 more for possible output
			InitSecBuffer(&inbuf[1], SECBUFFER_EMPTY, NULL, 0);
			InitSecBuffer(&inbuf[2], SECBUFFER_EMPTY, NULL, 0);
			InitSecBuffer(&inbuf[3], SECBUFFER_EMPTY, NULL, 0);
			InitSecBufferDesc(&inbuf_desc, inbuf, 4);
			// Decrypt the data
			sspistat = DecryptMessage(&context->Context, &inbuf_desc, 0, NULL);
			if (sspistat == SEC_E_OK || sspistat == SEC_I_RENEGOTIATE || sspistat == SEC_I_CONTEXT_EXPIRED) {
				if (inbuf[1].BufferType == SECBUFFER_DATA) {
					// Increase the output buffer size if needed
					size = inbuf[1].cbBuffer > SCHANNEL_FREE_BUFFER_SIZE ? inbuf[1].cbBuffer : SCHANNEL_FREE_BUFFER_SIZE;
					if (context->cbDecodedBuffer - context->dwDecodedOffset < size || context->cbDecodedBuffer < (unsigned)len) {
						context->cbDecodedBuffer = context->dwDecodedOffset + size;
						if (context->cbDecodedBuffer < (unsigned)len) {
							context->cbDecodedBuffer = (unsigned)len;
						}
						char* pNewBuffer = (char*)realloc(context->DecodedBuffer, context->cbDecodedBuffer);
						if (!pNewBuffer) {
							ret = -1;
							goto cleanup;
						}
						context->DecodedBuffer = pNewBuffer;
					}
					// Then copy the decrypted message to the buffer
					size = inbuf[1].cbBuffer;
					if (size) {
						memcpy(context->DecodedBuffer + context->dwDecodedOffset, inbuf[1].pvBuffer, size);
						context->dwDecodedOffset += size;
					}
				}
				// Check for any remaining encrypted data
				if (inbuf[3].BufferType == SECBUFFER_EXTRA && inbuf[3].cbBuffer > 0) {
					if (context->dwEncodedOffset > inbuf[3].cbBuffer) {
						memmove(context->EncodedBuffer, (context->EncodedBuffer + context->dwEncodedOffset) - inbuf[3].cbBuffer, inbuf[3].cbBuffer);
						context->dwEncodedOffset = inbuf[3].cbBuffer;
					}
				}
				else {
					context->dwEncodedOffset = 0;
				}

				if (sspistat == SEC_I_RENEGOTIATE) {
					if (context->dwEncodedOffset > 0) {
						// Error. Cannot renegotiate when there's still encrypted data in the buffer
						goto cleanup;
					}
					// Perform the SSL handshake again
					if (SSLHandshake(context, false) != 1) {
						// Renegotiation failed
						goto cleanup;
					}
					sspistat = SEC_E_OK;
					continue;
				}
				else if (sspistat == SEC_I_CONTEXT_EXPIRED) {
					// Connection closed by peer
					context->bSSLCloseNotify = true;
					context->bConnectionClosed = true;
					ret = 0;
					goto cleanup;
				}
			}
			else if (sspistat == SEC_E_INCOMPLETE_MESSAGE) {
				doagain = true;
			}
		}
	} while (doagain);

	ret = 0;

cleanup:
	size = (unsigned)len < context->dwDecodedOffset ? (unsigned)len : context->dwDecodedOffset;
	if (size > 0) {
		// There's data to return to the user
		memcpy(buf, context->DecodedBuffer, size);
		memmove(context->DecodedBuffer, context->DecodedBuffer + size, context->dwDecodedOffset - size);
		context->dwDecodedOffset -= size;
		return size;
	}
	// Otherwise it's an error
	return ret;
}

int SSLWrite(SSL_CONTEXT* context, char* buf, int len)
{
	SECURITY_STATUS sspistat = SEC_E_OK;
	SecBuffer outbuf[4];
	SecBufferDesc outbuf_desc;

	if (context->Sizes.cbMaximumMessage == 0) {
		sspistat = QueryContextAttributes(&context->Context, SECPKG_ATTR_STREAM_SIZES, &context->Sizes);
		if (sspistat != SEC_E_OK) {
			return -1;
		}
	}
	if (len > (int)context->Sizes.cbMaximumMessage) {
		len = (int)context->Sizes.cbMaximumMessage;
	}
	int data_size = context->Sizes.cbHeader + len + context->Sizes.cbTrailer;
	char* data = (char*)malloc(data_size);
	if (!data) {
		return -1;
	}
	InitSecBuffer(&outbuf[0], SECBUFFER_STREAM_HEADER, data, context->Sizes.cbHeader);
	InitSecBuffer(&outbuf[1], SECBUFFER_DATA, data + context->Sizes.cbHeader, len);
	InitSecBuffer(&outbuf[2], SECBUFFER_STREAM_TRAILER, data + context->Sizes.cbHeader + len, context->Sizes.cbTrailer);
	InitSecBuffer(&outbuf[3], SECBUFFER_EMPTY, NULL, 0);
	InitSecBufferDesc(&outbuf_desc, outbuf, 4);
	// Second buffer is the actual user data
	memcpy(outbuf[1].pvBuffer, buf, len);

	// Encrypt
	sspistat = EncryptMessage(&context->Context, 0, &outbuf_desc, 0);
	if (sspistat != SEC_E_OK) {
		free(data);
		return -1;
	}
	// Write encrypted data to socket
	int ret = send(context->sock, data, data_size, 0);

	free(data);
	return ret;
}

void SSLClose(SSL_CONTEXT* context)
{
	if (context->bIsConnected) {
		SECURITY_STATUS sspistat;
		SecBufferDesc BuffDesc;
		SecBuffer Buffer;
		SecBuffer outbuf;
		SecBufferDesc outbuf_desc;
		DWORD dwShutdown = SCHANNEL_SHUTDOWN;
		InitSecBuffer(&Buffer, SECBUFFER_TOKEN, &dwShutdown, sizeof(dwShutdown));
		InitSecBufferDesc(&BuffDesc, &Buffer, 1);
		// Not checking return value because there's nothing much
		// we can do anyway
		ApplyControlToken(&context->Context, &BuffDesc);
		InitSecBuffer(&outbuf, SECBUFFER_EMPTY, NULL, 0);
		InitSecBufferDesc(&outbuf_desc, &outbuf, 1);
		sspistat = InitializeSecurityContext(&context->Credential, &context->Context, context->ServerName,
			context->dwFlags, 0, 0, NULL, 0, &context->Context, &outbuf_desc, &context->ulContextAttr, &context->ContextExpiry);
		if (sspistat == SEC_E_OK || sspistat == SEC_I_CONTEXT_EXPIRED) {
			// Send any last pending encrypted data
			send(context->sock, (const char*)outbuf.pvBuffer, outbuf.cbBuffer, 0);
			FreeContextBuffer(outbuf.pvBuffer);
		}
		context->bIsConnected = false;
	}
	DeleteSecurityContext(&context->Context);
	FreeCredentialHandle(&context->Credential);
	free(context->DecodedBuffer);
	context->DecodedBuffer = NULL;
	context->cbDecodedBuffer = 0;
	context->dwDecodedOffset = 0;
	free(context->EncodedBuffer);
	context->EncodedBuffer = NULL;
	context->dwEncodedOffset = 0;
	context->cbEncodedBuffer = 0;
	free(context->ServerName);
	context->ServerName = NULL;

	closesocket(context->sock);
}
