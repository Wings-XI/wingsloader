#include "update.h"
#include "console.h"
#include <windows.h>
#include <WinInet.h>
#include <shellapi.h>
#include <WinCrypt.h>
#include <malloc.h>
#include <algorithm>
#include <cctype>

namespace xiloader
{

	bool GetLatestVersionInfo(LOADER_UPDATE_DETAILS* pDetails)
	{
		HINTERNET hInternet = InternetOpen("wingsxiloader/" LOADER_CURRENT_VERSION_STR,
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL,
			NULL,
			0);
		if (!hInternet) {
			return false;
		}
		HINTERNET hUrl = InternetOpenUrl(hInternet,
			"https://api.wingsxi.com/ldrupd/version.txt",
			NULL,
			0,
			INTERNET_FLAG_RELOAD,
			0);
		if (!hUrl) {
			InternetCloseHandle(hInternet);
			return false;
		}
		char bufVerData[4096] = { 0 };
		DWORD dwBytesRead = 0;
		DWORD rv = InternetReadFile(hUrl, bufVerData, sizeof(bufVerData), &dwBytesRead);
		InternetCloseHandle(hUrl);
		InternetCloseHandle(hInternet);
		if ((!rv) || (dwBytesRead == 0)) {
			return false;
		}
		bufVerData[sizeof(bufVerData) - 1] = '\0';
		char* pLineStart = bufVerData;
		char* pDataEnd = bufVerData + dwBytesRead;
		char* pLineEnd = 0;
		char* pNextLine = NULL;
		char szLine[4096] = { 0 };
		DWORD dwLineLen = 0;
		char* pNameStart = NULL;
		char* pNameEnd = NULL;
		char* pValStart = NULL;
		char* pValEnd = NULL;
		memset(pDetails, 0, sizeof(LOADER_UPDATE_DETAILS));
		while (pLineStart < pDataEnd) {
			pLineEnd = strchr(pLineStart, '\n');
			if (!pLineEnd) {
				pLineEnd = pLineStart + strlen(pLineStart);
			}
			pNextLine = pLineEnd + 1;
			if (pLineEnd == pLineStart) {
				pLineStart = pNextLine;
				continue;
			}
			while (pLineEnd > pLineStart && (*pLineEnd == '\n' || *pLineEnd == '\r' || *pLineEnd == '\0')) {
				pLineEnd--;
			}
			if (pLineEnd <= pLineStart) {
				pLineStart = pNextLine;
				continue;
			}
			dwLineLen = pLineEnd - pLineStart + 1;
			strncpy(szLine, pLineStart, min(sizeof(szLine) - 1, dwLineLen));
			if (dwLineLen < sizeof(szLine) - 1) {
				szLine[dwLineLen] = '\0';
			}
			pLineStart = pNextLine;
			pLineEnd = NULL;
			pNextLine = NULL;
			pNameStart = szLine;
			pValStart = strchr(szLine, ':');
			if (!pValStart) {
				continue;
			}
			*pValStart = '\0';
			pValStart++;
			pNameEnd = pValStart - 1;
			pValEnd = pValStart + strlen(pValStart);
			while (pNameStart < pValStart && *pNameStart < 0x21) {
				pNameStart++;
			}
			while (pNameEnd > pNameStart && *pNameEnd < 0x21) {
				pNameEnd--;
			}
			while (pValStart < pValEnd && *pValStart < 0x21) {
				pValStart++;
			}
			while (pValEnd > pValStart && *pValEnd < 0x21) {
				pValEnd--;
			}
			if (strcmp(pNameStart, "LATEST") == 0) {
				pDetails->dbLatestVersion = strtod(pValStart, NULL);
			}
			else if (strcmp(pNameStart, "REC") == 0) {
				pDetails->dbMinRecommended = strtod(pValStart, NULL);
			}
			else if (strcmp(pNameStart, "REQ") == 0) {
				pDetails->dbMinRequired = strtod(pValStart, NULL);
			}
			else if (strcmp(pNameStart, "URL") == 0) {
				strncpy(pDetails->szDownloadURL, pValStart, sizeof(pDetails->szDownloadURL) - 1);
			}
			else if (strcmp(pNameStart, "SHA") == 0) {
				strncpy(pDetails->szSHA, pValStart, sizeof(pDetails->szSHA) - 1);
			}
		}
		return true;
	}

	bool FilterCommandLine(char* pszFilteredCmd, size_t cbFilteredCmd, size_t* pcbBytesOut)
	{
		wchar_t* wszCommandLine = GetCommandLineW();
		int argc = 0;
		wchar_t** argv = CommandLineToArgvW(wszCommandLine, &argc);
		for (int i = 1; i < argc; i++) {
			if (wcscmp(argv[i], L"--oldfile") == 0) {
				i++;
				continue;
			}
			if (wcscmp(argv[i], L"--oldpid") == 0) {
				i++;
				continue;
			}
			if (wcscmp(argv[i], L"--runupdate") == 0) {
				continue;
			}
			if (wcscmp(argv[i], L"--finishupdate") == 0) {
				continue;
			}
			if (i != 1) {
				strncat(pszFilteredCmd, " ", cbFilteredCmd - strlen(pszFilteredCmd) - 1);
			}
			size_t cbCurrent = strlen(pszFilteredCmd);
			if (cbCurrent + 1 >= cbFilteredCmd) {
				return false;
			}
			wcstombs(pszFilteredCmd + cbCurrent, argv[i], cbFilteredCmd - cbCurrent - 1);
		}
		if (pcbBytesOut != NULL) {
			*pcbBytesOut = strlen(pszFilteredCmd);
		}
		return true;
	}
	
	DWORD DeleteOldFile(const char* pszOldFile)
	{
		if (!DeleteFile(pszOldFile)) {
			if (GetLastError() == ERROR_FILE_NOT_FOUND) {
				return 1;
			}
			// Possibly open, so try deleting on next restart
			if (!MoveFileEx(pszOldFile, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
				return 0;
			}
			else {
				return 2;
			}
		}
		return 1;
	}


	size_t Hex2Bin(const char* pszInput, char* pOutput)
	{
		size_t cbInput = strlen(pszInput);
		size_t cbOutput = 0;
		if (cbInput == 0 || (cbInput % 2 != 0)) {
			return 0;
		}
		char cByte = 0;
		for (size_t i = 0; i < cbInput; i+=2) {
			cByte = 0;
			for (size_t j = 0; j < 2; j++) {
				if ((pszInput[i + j] >= '0') && (pszInput[i + j] <= '9')) {
					cByte |= pszInput[i + j] - '0';
				}
				else if ((pszInput[i + j] >= 'A') && (pszInput[i + j] <= 'F')) {
					cByte |= pszInput[i + j] - 'A' + 0xA;
				}
				else if ((pszInput[i + j] >= 'a') && (pszInput[i + j] <= 'f')) {
					cByte |= pszInput[i + j] - 'a' + 0xA;
				}
				else {
					return 0;
				}
				if (j == 0) {
					cByte = cByte << 4;
				}
			}
			pOutput[cbOutput] = cByte;
			cbOutput++;
		}
		return cbOutput;
	}

	DWORD PerformUpdate(const char* pszOldFile, DWORD dwOldPID) {
		HANDLE hOldProcess = OpenProcess(SYNCHRONIZE, FALSE, dwOldPID);
		if (!hOldProcess) {
			if (GetLastError() != 87) {
				// 87 = Process doesn't exist (already exited)
				// Anything else is a failure
				return 0;
			}
		}
		if (hOldProcess) {
			// Wait for it to exit
			if (WaitForSingleObject(hOldProcess, 5000) != WAIT_OBJECT_0) {
				CloseHandle(hOldProcess);
				return 0;
			}
			CloseHandle(hOldProcess);
		}
		DWORD rv = DeleteOldFile(pszOldFile);
		if (rv != 1) {
			return rv;
		}
		// Copy ourselves where the old file was
		char szOwnFileName[MAX_PATH + 1] = { 0 };
		rv = GetModuleFileName(NULL, szOwnFileName, sizeof(szOwnFileName));
		if (rv == 0 || rv >= sizeof(szOwnFileName)) {
			return 0;
		}
		if (!CopyFile(szOwnFileName, pszOldFile, FALSE)) {
			return 0;
		}
		char* pszNewCommandLine = (char*)malloc(10240);
		if (!pszNewCommandLine) {
			return 0;
		}
		memset(pszNewCommandLine, 0, 10240);
		strncpy(pszNewCommandLine, pszOldFile, 10239);
		strncat(pszNewCommandLine, " ", 10239 - strlen(pszNewCommandLine));
		if (!FilterCommandLine(pszNewCommandLine + strlen(pszNewCommandLine), 10239 - strlen(pszNewCommandLine), NULL)) {
			free(pszNewCommandLine);
			return 0;
		}
		strncat(pszNewCommandLine, "--finishupdate --oldfile ", 10239 - strlen(pszNewCommandLine));
		strncat(pszNewCommandLine, szOwnFileName, 10239 - strlen(pszNewCommandLine));
		strncat(pszNewCommandLine, " --oldpid ", 10239 - strlen(pszNewCommandLine));
		snprintf(pszNewCommandLine + strlen(pszNewCommandLine), 10239 - strlen(pszNewCommandLine), "%u", GetCurrentProcessId());
		STARTUPINFO StartupInfo = { 0 };
		StartupInfo.cb = sizeof(StartupInfo);
		PROCESS_INFORMATION ProcessInformation = { 0 };
		if (!CreateProcess(pszOldFile, pszNewCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInformation)) {
			free(pszNewCommandLine);
			return 0;
		}
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
		free(pszNewCommandLine);
		return 1;
	}

	bool DownloadAndRunUpdate(const LOADER_UPDATE_DETAILS* pDetails)
	{
		HINTERNET hInternet = InternetOpen("wingsxiloader/" LOADER_CURRENT_VERSION_STR,
			INTERNET_OPEN_TYPE_PRECONFIG,
			NULL,
			NULL,
			0);
		if (!hInternet) {
			return false;
		}
		HINTERNET hUrl = InternetOpenUrl(hInternet,
			pDetails->szDownloadURL,
			NULL,
			0,
			INTERNET_FLAG_RELOAD,
			0);
		if (!hUrl) {
			InternetCloseHandle(hInternet);
			return false;
		}
		char szTempFile[MAX_PATH + 1] = { 0 };
		DWORD rv = GetTempPath(sizeof(szTempFile) - 1, szTempFile);
		if (rv == 0 || rv > sizeof(szTempFile) - 1) {
			InternetCloseHandle(hUrl);
			InternetCloseHandle(hInternet);
			return false;
		}
		strncat(szTempFile, "xiloader_update.exe", sizeof(szTempFile) - strlen(szTempFile) - 1);
		FILE* hTempFile = fopen(szTempFile, "wb");
		if (!hTempFile) {
			InternetCloseHandle(hUrl);
			InternetCloseHandle(hInternet);
			return false;
		}
		char bufData[4096] = { 0 };
		DWORD dwBytesRead = 0;
		DWORD dwBytesWritten = 0;
		HCRYPTPROV hCryptProv = NULL;
		if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
			fclose(hTempFile);
			InternetCloseHandle(hUrl);
			InternetCloseHandle(hInternet);
			return false;
		}
		HCRYPTHASH hHash = NULL;
		if (!CryptCreateHash(hCryptProv, CALG_SHA_256, NULL, 0, &hHash)) {
			CryptReleaseContext(hCryptProv, 0);
			fclose(hTempFile);
			InternetCloseHandle(hUrl);
			InternetCloseHandle(hInternet);
			return false;
		}
		rv = InternetReadFile(hUrl, bufData, sizeof(bufData), &dwBytesRead);
		while (rv && dwBytesRead > 0) {
			dwBytesWritten = fwrite(bufData, 1, dwBytesRead, hTempFile);
			if (dwBytesWritten != dwBytesRead) {
				break;
			}
			if (!CryptHashData(hHash, (BYTE*)bufData, dwBytesRead, 0)) {
				break;
			}
			rv = InternetReadFile(hUrl, bufData, sizeof(bufData), &dwBytesRead);
		}
		char bufHash[128] = { 0 };
		DWORD cbHash = sizeof(bufHash);
		if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)bufHash, &cbHash, 0)) {
			rv = 0;
		}
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		fclose(hTempFile);
		InternetCloseHandle(hUrl);
		InternetCloseHandle(hInternet);
		if (!rv || dwBytesRead != 0) {
			return false;
		}
		char bufExpectedHash[32] = { 0 };
		if (strlen(pDetails->szSHA) != sizeof(bufExpectedHash) * 2) {
			return false;
		}
		if (Hex2Bin(pDetails->szSHA, bufExpectedHash) != sizeof(bufExpectedHash)) {
			return false;
		}
		if (memcmp(bufHash, bufExpectedHash, sizeof(bufExpectedHash)) != 0) {
			return false;
		}
		char* pszNewCommandLine = (char*)malloc(10240);
		if (!pszNewCommandLine) {
			return 0;
		}
		char szOwnFileName[MAX_PATH + 1] = { 0 };
		rv = GetModuleFileName(NULL, szOwnFileName, sizeof(szOwnFileName));
		if (rv == 0 || rv >= sizeof(szOwnFileName)) {
			return 0;
		}
		memset(pszNewCommandLine, 0, 10240);
		strncpy(pszNewCommandLine, szTempFile, 10239);
		strncat(pszNewCommandLine, " ", 10239 - strlen(pszNewCommandLine));
		if (!FilterCommandLine(pszNewCommandLine + strlen(pszNewCommandLine), 10239 - strlen(pszNewCommandLine), NULL)) {
			free(pszNewCommandLine);
			return 0;
		}
		strncat(pszNewCommandLine, "--runupdate --oldfile ", 10239 - strlen(pszNewCommandLine));
		strncat(pszNewCommandLine, szOwnFileName, 10239 - strlen(pszNewCommandLine));
		strncat(pszNewCommandLine, " --oldpid ", 10239 - strlen(pszNewCommandLine));
		snprintf(pszNewCommandLine + strlen(pszNewCommandLine), 10239 - strlen(pszNewCommandLine), "%u", GetCurrentProcessId());
		STARTUPINFO StartupInfo = { 0 };
		StartupInfo.cb = sizeof(StartupInfo);
		PROCESS_INFORMATION ProcessInformation = { 0 };
		if (!CreateProcess(szTempFile, pszNewCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo, &ProcessInformation)) {
			free(pszNewCommandLine);
			return 0;
		}
		CloseHandle(ProcessInformation.hThread);
		CloseHandle(ProcessInformation.hProcess);
		free(pszNewCommandLine);
		return 1;
	}

	DWORD CheckUpdateUI()
	{
		xiloader::console::output(xiloader::color::info, "Checking for updates...");
		LOADER_UPDATE_DETAILS Details = { 0 };
		if (!GetLatestVersionInfo(&Details)) {
			return 0;
		}
		if (Details.dbLatestVersion <= LOADER_CURRENT_VERSION) {
			xiloader::console::output(xiloader::color::info, "Already using the latest version.");
			return 1;
		}
		xiloader::console::output(xiloader::color::debug, "Latest version: %.2f", Details.dbLatestVersion);
		xiloader::console::output(xiloader::color::warning, "A new version of the bootloader is available.");
		DWORD dwType = 0;
		if (Details.dbMinRecommended > LOADER_CURRENT_VERSION) {
			dwType = 1;
		}
		if (Details.dbMinRequired > LOADER_CURRENT_VERSION) {
			dwType = 2;
		}
		if (dwType == 2) {
			xiloader::console::output(xiloader::color::warning, "This is a required update.");
		}
		else if (dwType == 1) {
			xiloader::console::output(xiloader::color::warning, "This is a recommended update.");
		}
		else {
			xiloader::console::output(xiloader::color::warning, "This is an optional update.");
		}

		std::string answer;
		char szAnswer[16] = { 0 };
		int cbAnswer = 0;
		DWORD dwDecision = 0;
		do {
			if (dwType) {
				printf("Would you like to install the update now? (Y/N, default=Y) ");
			}
			else {
				printf("Would you like to install the update now? (Y/N, default=N) ");
			}
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
				if (dwType) {
					dwDecision = 1;
				}
				else {
					dwDecision = 2;
				}
			}
			else {
				xiloader::console::output(xiloader::color::warning, "Please type \"yes\" or \"no\"");
			}
		} while (dwDecision == 0);
		if (dwDecision == 1) {
			xiloader::console::output(xiloader::color::info, "Downloading update, please wait.");
			if (!DownloadAndRunUpdate(&Details)) {
				xiloader::console::output(xiloader::color::error, "Update failed!");
				if (dwType == 2) {
					return 2;
				}
				return 0;
			}
			return 2;
		}
		else {
			if (dwType == 2) {
				xiloader::console::output(xiloader::color::error, "Cannot continue.");
				return 2;
			}
		}
		return 1;
	}
}
