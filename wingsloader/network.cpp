/*
===========================================================================

Copyright (c) 2010-2014 Darkstar Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

This file is part of DarkStar-server source code.

===========================================================================
*/

#include "network.h"
#include "functions.h"
#include <algorithm>
#include <cctype>

/* Externals */
extern std::string g_ServerAddress;
extern std::string g_Username;
extern std::string g_Password;
extern std::string g_ServerPort;
extern std::string g_DataPort;
extern std::string g_POLPort;
extern char* g_CharacterList;
extern bool g_IsRunning;
extern bool g_Secure;
extern bool g_SecureVerify;
extern std::string g_ServerHostname;

namespace xiloader
{
	/* Send secure/unsecure wrapper */
	int xi_send(datasocket* sock, char* buf, int len)
	{
		if (g_Secure) {
			return SSLWrite(&sock->SSL, buf, len);
		}
		else {
			return send(sock->s, buf, len, 0);
		}
	}

	/* Receive secure/unsecure wrapper */
	int xi_recv(datasocket* sock, char* buf, int len)
	{
		if (g_Secure) {
			return SSLRead(&sock->SSL, buf, len);
		}
		else {
			return recv(sock->s, buf, len, 0);
		}
	}

    /**
     * @brief Creates a connection on the given port.
     *
     * @param sock      The datasocket object to store information within.
     * @param port      The port to create the connection on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateConnection(datasocket* sock, const char* port, bool secure)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        /* Attempt to get the server information. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(g_ServerAddress.c_str(), port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain remote server information.");
            return 0;
        }

        /* Determine which address is valid to connect.. */
        for (auto ptr = addr; ptr != NULL; ptr->ai_next)
        {
            /* Attempt to create the socket.. */
            sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock->s == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Failed to create socket.");

                freeaddrinfo(addr);
                return 0;
            }

            /* Attempt to connect to the server.. */
            if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

                closesocket(sock->s);
                sock->s = INVALID_SOCKET;
                return 0;
            }
			
			/* Establish secure connection if needed */
			if (secure) {
				memset(&sock->SSL, 0, sizeof(sock->SSL));
				DWORD result = SSLConnect(sock->s, g_ServerHostname.c_str(), &sock->SSL, g_SecureVerify);
				if (result == 2) {
					// Certificate validation failed
					closesocket(sock->s);
					sock->s = INVALID_SOCKET;
					xiloader::console::output(xiloader::color::warning, "The remote server SSL certificate could not be validated.");
					xiloader::console::output(xiloader::color::warning, "This could put your password at risk of being intercepted by others.");
					DWORD dwDecision = 0;
					std::string answer;
					char szAnswer[16] = { 0 };
					int cbAnswer = 0;
					do {
						printf("Do you wish to connect anyway? (Y/N, default=N) ");
						fgets(szAnswer, sizeof(szAnswer) - 1, stdin);
						cbAnswer = strlen(szAnswer);
						if (szAnswer[cbAnswer - 1] == '\n') {
							szAnswer[cbAnswer - 1] = '\0';
							cbAnswer--;
						}
						answer = szAnswer;
						if (answer != "") {
							std::transform(answer.begin(), answer.end(), answer.begin(),
								[](unsigned char c){ return std::tolower(c); });
						}
						if (answer == "y" || answer == "yes") {
							dwDecision = 1;
							break;
						}
						else if (answer == "n" || answer == "no") {
							dwDecision = 2;
						}
						else if (answer == "") {
							dwDecision = 2;
						}
						else {
							xiloader::console::output(xiloader::color::warning, "Please type \"yes\" or \"no\"");
						}
					} while (dwDecision == 0);
					if (dwDecision == 1) {
						g_SecureVerify = false;
						/* Attempt to create the socket.. */
						sock->s = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
						if (sock->s == INVALID_SOCKET)
						{
							xiloader::console::output(xiloader::color::error, "Failed to create socket.");

							freeaddrinfo(addr);
							return 0;
						}

						/* Attempt to connect to the server.. */
						if (connect(sock->s, ptr->ai_addr, ptr->ai_addrlen) == SOCKET_ERROR)
						{
							xiloader::console::output(xiloader::color::error, "Failed to connect to server!");

							closesocket(sock->s);
							sock->s = INVALID_SOCKET;
							return 0;
						}
						result = SSLConnect(sock->s, g_ServerHostname.c_str(), &sock->SSL, g_SecureVerify);
					}
				}
				if (result != 1) {
					xiloader::console::output(xiloader::color::error, "Failed to establish SSL session!");

					closesocket(sock->s);
					sock->s = INVALID_SOCKET;
					return 0;
				}
			}

            xiloader::console::output(xiloader::color::info, "Connected to server!");
            break;
        }

        std::string localAddress = "";

        /* Attempt to locate the client address.. */
        char hostname[1024] = { 0 };
        if (gethostname(hostname, sizeof(hostname)) == 0)
        {
            PHOSTENT hostent = NULL;
            if ((hostent = gethostbyname(hostname)) != NULL)
                localAddress = inet_ntoa(*(struct in_addr*)*hostent->h_addr_list);
        }

        sock->LocalAddress = inet_addr(localAddress.c_str());
        sock->ServerAddress = inet_addr(g_ServerAddress.c_str());

        return 1;
    }

    /**
     * @brief Creates a listening server on the given port and protocol.
     *
     * @param sock      The socket object to bind to.
     * @param protocol  The protocol to use on the new listening socket.
     * @param port      The port to bind to listen on.
     *
     * @return True on success, false otherwise.
     */
    bool network::CreateListenServer(SOCKET* sock, int protocol, const char* port)
    {
        struct addrinfo hints;
        memset(&hints, 0x00, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = protocol == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = protocol;
        hints.ai_flags = AI_PASSIVE;

        /* Attempt to resolve the local address.. */
        struct addrinfo* addr = NULL;
        if (getaddrinfo(NULL, port, &hints, &addr))
        {
            xiloader::console::output(xiloader::color::error, "Failed to obtain local address information.");
            return false;
        }

        /* Create the listening socket.. */
        *sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (*sock == INVALID_SOCKET)
        {
            xiloader::console::output(xiloader::color::error, "Failed to create listening socket.");

            freeaddrinfo(addr);
            return false;
        }

        /* Bind to the local address.. */
        if (bind(*sock, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
        {
            xiloader::console::output(xiloader::color::error, "Failed to bind to listening socket.");

            freeaddrinfo(addr);
            closesocket(*sock);
            *sock = INVALID_SOCKET;
            return false;
        }

        freeaddrinfo(addr);

        /* Attempt to listen for clients if we are using TCP.. */
        if (protocol == IPPROTO_TCP)
        {
            if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Failed to listen for connections.");

                closesocket(*sock);
                *sock = INVALID_SOCKET;
                return false;
            }
        }

        return true;
    }


    /**
     * @brief Resolves the given hostname to its long ip format.
     *
     * @param host      The host name to resolve.
     * @param lpOutput  Pointer to a ULONG to store the result.
     *
     * @return True on success, false otherwise.
     */
    bool network::ResolveHostname(const char* host, PULONG lpOutput)
    {
        struct addrinfo hints, *info = 0;
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(host, "1000", &hints, &info))
            return false;

        *lpOutput = ((struct sockaddr_in*)info->ai_addr)->sin_addr.S_un.S_addr;

        freeaddrinfo(info);
        return true;
    }

	std::string network::TranslateErrorCode(AUTHENTICATION_ERROR ErrorCode)
	{
		switch (ErrorCode) {
		case AUTH_SUCCESS:
			return "Authentication succeeded.";
		case AUTH_NO_USER_OR_BAD_PASSWORD:
			return "Unknown username or incorrect password.";
		case AUTH_USERNAME_TAKEN:
			return "The chosen username is already taken.";
		case AUTH_PASSWORD_TOO_WEAK:
			return "The chosen password is too weak.";
		case AUTH_INTERNAL_FAILURE:
			return "Internal server failure.";
		case AUTH_ACCOUNT_DISABLED:
			return "The account is disabled or banned.";
		case AUTH_MAINTENANCE_MODE:
			return "The server is currently in maintenance mode.";
		case AUTH_BOOTLOADER_SIGNUP_DISABLED:
			return "User registration through the bootloader is disabled on this server.";
		case AUTH_ANOTHER_ACCOUNT_SHARES_IP:
			return "Another account is already associated to this IP address.";
		case AUTH_SESSION_EXISTS:
			return "A user is already connected to this account from another IP address.";
		case AUTH_IP_BLOCKED:
			return "Connections from this IP address are not allowed.";
		case AUTH_IP_LOCKED_OUT:
			return "Too many failed connections. Try again later.";
		default:
			return "Unknown error: " + std::to_string(ErrorCode);
		}
	}

    /**
     * @brief Verifies the players login information; also handles creating new accounts.
     *
     * @param sock      The datasocket object with the connection socket.
     *
     * @return True on success, false otherwise.
     */
    bool network::VerifyAccount(datasocket* sock)
    {
        static bool bFirstLogin = true;
		uint16_t wFailureReason = 0;
		std::string strFailReason;
		uint16_t wSendSize = 33;

        unsigned char recvBuffer[1024] = { 0 };
        unsigned char sendBuffer[1024] = { 0 };

        /* Create connection if required.. */
        if (sock->s == NULL || sock->s == INVALID_SOCKET)
        {
            if (!xiloader::network::CreateConnection(sock, g_ServerPort.c_str(), g_Secure))
                return false;
        }

        /* Determine if we should auto-login.. */
        bool bUseAutoLogin = !g_Username.empty() && !g_Password.empty() && bFirstLogin;
        if (bUseAutoLogin)
            xiloader::console::output(xiloader::color::lightgreen, "Autologin activated!");

        if (!bUseAutoLogin)
        {
            xiloader::console::output("==========================================================");
            xiloader::console::output("What would you like to do?");
            xiloader::console::output("   1.) Login");
            xiloader::console::output("   2.) Create New Account");
			xiloader::console::output("   3.) Change Password");
            xiloader::console::output("==========================================================");
            printf("\nEnter a selection: ");

            std::string input;
			std::string strNewPassword;
            std::cin >> input;
            std::cout << std::endl;

            if (input == "1")
            {
				/* User wants to log into an existing account.. */
				xiloader::console::output("Please enter your login information.");
                std::cout << "\nUsername: ";
                std::cin >> g_Username;
                std::cout << "Password: ";
				g_Password = functions::ReadPassword();

                sendBuffer[0x20] = 0x10;
            }
            else if (input == "2")
            {
				/* User wants to create a new account.. */
				while (true) {
					xiloader::console::output("Please enter your desired login information.");
					std::cout << "\nUsername (3-15 characters): ";
					std::cin >> g_Username;
					std::cout << "Password (6-15 characters): ";
					g_Password = functions::ReadPassword();
					std::cout << "Repeat Password           : ";
					input = functions::ReadPassword();
					std::cout << std::endl;

					if (input != g_Password)
					{
						xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
						continue;
					}
					break;
				}

                sendBuffer[0x20] = 0x20;
            }
			else if (input == "3")
			{
				/* User wants to change password.. */
				while (true) {
					xiloader::console::output("Please enter your login information.");
					std::cout << "\nUsername: ";
					std::cin >> g_Username;
					std::cout << "Password: ";
					g_Password = functions::ReadPassword();
					std::cout << "New Password (6-15 characters): ";
					strNewPassword = functions::ReadPassword();
					std::cout << "Repeat Password               : ";
					input = functions::ReadPassword();
					std::cout << std::endl;

					if (input != strNewPassword)
					{
						xiloader::console::output(xiloader::color::error, "Passwords did not match! Please try again.");
						continue;
					}
					break;
				}

				memcpy(sendBuffer + 0x21, strNewPassword.c_str(), 16);
				sendBuffer[0x20] = 0x80;
				wSendSize += 16;
			}

            std::cout << std::endl;
        }
        else
        {
            /* User has auto-login enabled.. */
            sendBuffer[0x20] = 0x10;
        }
		bFirstLogin = false;

        /* Copy username and password into buffer.. */
        memcpy(sendBuffer + 0x00, g_Username.c_str(), 16);
        memcpy(sendBuffer + 0x10, g_Password.c_str(), 16);

        /* Send info to server and obtain response.. */
		xi_send(sock, (char*)sendBuffer, wSendSize);
		xi_recv(sock, (char*)recvBuffer, 16);
        // send(sock->s, (char*)sendBuffer, wSendSize, 0);
        // recv(sock->s, (char*)recvBuffer, 16, 0);

        /* Handle the obtained result.. */
        switch (recvBuffer[0])
        {
        case 0x0001: // Success (Login)
            xiloader::console::output(xiloader::color::success, "Successfully logged in as %s!", g_Username.c_str());
            sock->AccountId = *(UINT32*)(recvBuffer + 0x01);
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return true;

        case 0x0002: // Error (Login)
			wFailureReason = *reinterpret_cast<uint16_t*>(recvBuffer + 5);
			strFailReason = wFailureReason ? TranslateErrorCode(static_cast<AUTHENTICATION_ERROR>(wFailureReason)) : "";
            xiloader::console::output(xiloader::color::error, "Failed to login. %s", strFailReason.c_str());
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case 0x0003: // Success (Create Account)
            xiloader::console::output(xiloader::color::success, "Account successfully created!");
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

        case 0x0004: // Error (Create Account)
			wFailureReason = *reinterpret_cast<uint16_t*>(recvBuffer + 5);
			strFailReason = wFailureReason ? TranslateErrorCode(static_cast<AUTHENTICATION_ERROR>(wFailureReason)) : "";
			xiloader::console::output(xiloader::color::error, "Failed to create the new account. %s", strFailReason.c_str());
            closesocket(sock->s);
            sock->s = INVALID_SOCKET;
            return false;

		case 0x0005: // Success (Change Password)
			xiloader::console::output(xiloader::color::success, "Password changed successfully!");
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;

		case 0x0006: // Error (Change Password)
			wFailureReason = *reinterpret_cast<uint16_t*>(recvBuffer + 5);
			strFailReason = wFailureReason ? TranslateErrorCode(static_cast<AUTHENTICATION_ERROR>(wFailureReason)) : "";
			xiloader::console::output(xiloader::color::error, "Failed to change password. %s", strFailReason.c_str());
			closesocket(sock->s);
			sock->s = INVALID_SOCKET;
			return false;

		}

        /* We should not get here.. */
        closesocket(sock->s);
        sock->s = INVALID_SOCKET;
        return false;
    }

    /**
     * @brief Data communication between the local client and the game server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiDataComm(LPVOID lpParam)
    {
        auto sock = (xiloader::datasocket*)lpParam;

        int sendSize = 0;
        char recvBuffer[4096] = { 0 };
        char sendBuffer[4096] = { 0 };

        while (g_IsRunning)
        {
            /* Attempt to receive the incoming data.. */
            //struct sockaddr_in client;
            //unsigned int socksize = sizeof(client);
            //if (recvfrom(sock->s, recvBuffer, sizeof(recvBuffer), 0, (struct sockaddr*)&client, (int*)&socksize) <= 0)
			if (xi_recv(sock, recvBuffer, sizeof(recvBuffer)) <= 0)
				continue;

            switch (recvBuffer[0])
            {
            case 0x0001:
                sendBuffer[0] = 0xA1u;
                memcpy(sendBuffer + 0x01, &sock->AccountId, 4);
                memcpy(sendBuffer + 0x05, &sock->ServerAddress, 4);
                xiloader::console::output(xiloader::color::warning, "Sending account id..");
                sendSize = 9;
                break;

            case 0x0002:
            case 0x0015:
                memcpy(sendBuffer, (char*)"\xA2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58\xE0\x5D\xAD\x00\x00\x00\x00", 25);
                xiloader::console::output(xiloader::color::warning, "Sending key..");
                sendSize = 25;
                break;

            case 0x0003:
                xiloader::console::output(xiloader::color::warning, "Receiving character list..");
                for (auto x = 0; x <= recvBuffer[1]; x++)
                {
                    g_CharacterList[0x00 + (x * 0x68)] = 1;
                    g_CharacterList[0x02 + (x * 0x68)] = 1;
                    g_CharacterList[0x10 + (x * 0x68)] = (char)x;
                    g_CharacterList[0x11 + (x * 0x68)] = 0x80u;
                    g_CharacterList[0x18 + (x * 0x68)] = 0x20;
                    g_CharacterList[0x28 + (x * 0x68)] = 0x20;

#if defined(DEBUG) || defined(_DEBUG)
					DWORD dwCharID = *(recvBuffer + 0x10 * (x + 1) + 4);
					DWORD dwContentID = *(recvBuffer + 0x10 * (x + 1));
					xiloader::console::output(xiloader::color::warning, "Charater %u: ContentID=%u, CharID=%u", x, dwContentID, dwCharID);
#endif
                    memcpy(g_CharacterList + 0x04 + (x * 0x68), recvBuffer + 0x10 * (x + 1) + 4, 4); // Character Id
                    memcpy(g_CharacterList + 0x08 + (x * 0x68), recvBuffer + 0x10 * (x + 1), 4); // Content Id
                }
                sendSize = 0;
                break;
            }

            if (sendSize == 0)
                continue;

            /* Send the response buffer to the server.. */
            //auto result = sendto(sock->s, sendBuffer, sendSize, 0, (struct sockaddr*)&client, socksize);
			auto result = xi_send(sock, sendBuffer, sendSize);
			if (sendSize == 72 || result == SOCKET_ERROR || sendSize == -1)
            {
                shutdown(sock->s, SD_SEND);
                closesocket(sock->s);
                sock->s = INVALID_SOCKET;

                xiloader::console::output("Server connection done; disconnecting!");
                return 0;
            }

            sendSize = 0;
            Sleep(100);
        }

        return 0;
    }

    /**
     * @brief Data communication between the local client and the lobby server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolDataComm(LPVOID lpParam)
    {
        SOCKET client = *(SOCKET*)lpParam;
        unsigned char recvBuffer[1024] = { 0 };
        int result = 0, x = 0;
        time_t t = 0;
        bool bIsNewChar = false;

        do
        {
            /* Attempt to receive incoming data.. */
            result = recv(client, (char*)recvBuffer, sizeof(recvBuffer), 0);
            if (result <= 0)
            {
                xiloader::console::output(xiloader::color::error, "Client recv failed: %d", WSAGetLastError());
                break;
            }

            char temp = recvBuffer[0x04];
            memset(recvBuffer, 0x00, 32);

            switch (x)
            {
            case 0:
                recvBuffer[0] = 0x81;
                t = time(NULL);
                memcpy(recvBuffer + 0x14, &t, 4);
                result = 24;
                break;

            case 1:
                if (temp != 0x28)
                    bIsNewChar = true;
                recvBuffer[0x00] = 0x28;
                recvBuffer[0x04] = 0x20;
                recvBuffer[0x08] = 0x01;
                recvBuffer[0x0B] = 0x7F;
                result = bIsNewChar ? 144 : 24;
                if (bIsNewChar) bIsNewChar = false;
                break;
            }

            /* Echo back the buffer to the server.. */
            if (send(client, (char*)recvBuffer, result, 0) == SOCKET_ERROR)
            {
                xiloader::console::output(xiloader::color::error, "Client send failed: %d", WSAGetLastError());
                break;
            }

            /* Increase the current packet count.. */
            x++;
            if (x == 3)
                break;

        } while (result > 0);

        /* Shutdown the client socket.. */
        if (shutdown(client, SD_SEND) == SOCKET_ERROR)
            xiloader::console::output(xiloader::color::error, "Client shutdown failed: %d", WSAGetLastError());
        closesocket(client);

        return 0;
    }

    /**
     * @brief Starts the data communication between the client and server.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::FFXiServer(LPVOID lpParam)
    {
        /* Attempt to create connection to the server.. */
        if (!xiloader::network::CreateConnection((xiloader::datasocket*)lpParam, g_DataPort.c_str(), g_Secure))
            return 1;

        /* Attempt to start data communication with the server.. */
        CreateThread(NULL, 0, xiloader::network::FFXiDataComm, lpParam, 0, NULL);
        Sleep(200);

        return 0;
    }

    /**
     * @brief Starts the local listen server to lobby server communications.
     *
     * @param lpParam   Thread param object.
     *
     * @return Non-important return.
     */
    DWORD __stdcall network::PolServer(LPVOID lpParam)
    {
        UNREFERENCED_PARAMETER(lpParam);

        SOCKET sock, client;

        /* Attempt to create listening server.. */
        if (!xiloader::network::CreateListenServer(&sock, IPPROTO_TCP, g_POLPort.c_str()))
            return 1;

        while (g_IsRunning)
        {
            /* Attempt to accept incoming connections.. */
            if ((client = accept(sock, NULL, NULL)) == INVALID_SOCKET)
            {
                xiloader::console::output(xiloader::color::error, "Accept failed: %d", WSAGetLastError());

                closesocket(sock);
                return 1;
            }

            /* Start data communication for this client.. */
            CreateThread(NULL, 0, xiloader::network::PolDataComm, &client, 0, NULL);
        }

        closesocket(sock);
        return 0;
    }

}; // namespace xiloader
