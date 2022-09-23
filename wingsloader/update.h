/**
 *	@file update.h
 *	Self update routine
 *	@author Twilight
 *	@license GPLv3
 */

#ifndef INC_UPDATE_H
#define INC_UPDATE_H

#define LOADER_CURRENT_VERSION 1.30
#define LOADER_CURRENT_VERSION_STR "1.30"

#include <string>
#include <windows.h>

namespace xiloader
{

	struct LOADER_UPDATE_DETAILS
	{
		double dbMinRequired;
		double dbMinRecommended;
		double dbLatestVersion;
		char szDownloadURL[2048];
		char szSHA[256];
	};

	/**
	 *	Get details of the latest version
	 *	@param pDetails OUT receives the details
	 *	@return true if successful
	 */
	bool GetLatestVersionInfo(LOADER_UPDATE_DETAILS* pDetails);

	/**
	 *	Last update step, attempt to delete the temporary file.
	 *	If open, delete on next restart.
	 *	@param pszOldFile File to delete
	 *	@return 1 if successful, 0 if failed, 2 if will be deleted on restart
	 */
	DWORD DeleteOldFile(const char* pszOldFile);

	/**
	 *	Second update step, copy ourselves overwriting the old file
	 *	and run the executable from the final place.
	 *	@param pszOldFile The original location of the file
	 *	@param dwOldPID Our own PID
	 *	@return 1 if successful, 0 if failed, 2 if restart required
	 */
	DWORD PerformUpdate(const char* pszOldFile, DWORD dwOldPID);

	/**
	 *	First update step, download the update into a temporary directory
	 *	and run it from there with specific update arguments.
	 *	@param pDetails Update details acquired through GetLatestVersionInfo
	 *	@return true on success, false on failure
	 */
	bool DownloadAndRunUpdate(const LOADER_UPDATE_DETAILS* pDetails);

	/**
	 *	Check for updates, prompt the user if an update is necessary and
	 *	update if the user decides to do so
	 *	@return 1 if OK to continue, 2 if need to exit, 0 on failure
	 */
	DWORD CheckUpdateUI();
}

#endif