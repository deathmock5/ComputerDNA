#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <Iphlpapi.h>
#include <tchar.h>
#include <Assert.h>
#include <cstring>
#include <sstream>
#include <memory>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "version.lib" )

#include "InstalledPrograms.h"
#include "CPUID.h"
#include "SHA1.h"

using namespace std;

/* Dont build "Fingerprint" of computer. Instead, build a DNA list. Then compare "chromasomes".

1: Installed programs & Version.
2: Volumes & Serial Numbers
3: Connected Devices
4: Network Interfaces
5: System Specs
6: Opperating System
7: CPU
8: Drivers

Chromasomes are in KEY-KEY value pairs. Use Sha1 Hasing to protect Privacy of user.
Diffrent systems have diffrent sets of chromasomes.

Helps prevent ban doging and mitigates unessisary bans.

*/

std::string stringToSha1(const std::string& s) {
	return sha1(s);
}

template<typename T1,typename T2>
void printNucleotide(const T1& t1,const T2& t2) {
	std::cout << stringToSha1(t1) << "-" << stringToSha1(t2) << std::endl;
}

wchar_t *convertCharArrayToLPCWSTR(const char* charArray){
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

void installedProgramUnique() {
	vector<Software>* list = InstalledPrograms::GetInstalledPrograms(false);
	for (vector<Software>::iterator iter = list->begin(); iter != list->end(); iter++)
	{
		printNucleotide(std::string(iter->DisplayName.begin(), iter->DisplayName.end()), std::string(iter->Version.begin(),iter->Version.end()));
		//wcout << iter->DisplayName << L"  " << iter->Version << L"  " << endl;
	}
}
void volumeInformationUnique() {
	DWORD drives = GetLogicalDrives();
	for (int i = 0; i<26; i++)
	{
		if ((drives & (1 << i)))
		{ 
			std::string drivename = "";
			drivename += (char)('a' + i);
			drivename += ":\\";
			WCHAR volumeName[MAX_PATH + 1] = { 0 };
			WCHAR fileSystemName[MAX_PATH + 1] = { 0 };
			DWORD serialNumber = 0;
			DWORD maxComponentLen = 0;
			DWORD fileSystemFlags = 0;

			if (GetVolumeInformation(
				convertCharArrayToLPCWSTR(drivename.c_str()), // L"\\MyServer\MyShare\"
				volumeName,
				sizeof(volumeName),
				&serialNumber,
				&maxComponentLen,
				&fileSystemFlags,
				fileSystemName,
				sizeof(fileSystemName)) == TRUE)
			{
				printf("%s %lu\n",drivename.c_str(), serialNumber);
				//wprintf(L"Serial Number: %lu\n", serialNumber);
				//wprintf(L"File System Name: %s\n", fileSystemName);
				//wprintf(L"Max Component Length: %lu\n", maxComponentLen);
				//wprintf(L"File system flags: 0X%.08X\n", fileSystemFlags);
			}
/*
			else

			{
				wprintf(L"GetVolumeInformation() failed, error %u\n", GetLastError());
			}*/
		}
	}
}
void hardwareInformationUnique() {

	// Get Number Of Devices
	UINT nDevices = 0;
	GetRawInputDeviceList(NULL, &nDevices, sizeof(RAWINPUTDEVICELIST));

	// Got Any?
	if (nDevices < 1)
	{
		// Exit
		cout << "ERR: 0 Devices?";
		cin.get();
		return;
	}

	// Allocate Memory For Device List
	PRAWINPUTDEVICELIST pRawInputDeviceList;
	pRawInputDeviceList = new RAWINPUTDEVICELIST[sizeof(RAWINPUTDEVICELIST) * nDevices];

	// Got Memory?
	if (pRawInputDeviceList == NULL){
		// Error
		cout << "ERR: Could not allocate memory for Device List.";
		cin.get();
		return;
	}

	// Fill Device List Buffer
	int nResult;
	nResult = GetRawInputDeviceList(pRawInputDeviceList, &nDevices, sizeof(RAWINPUTDEVICELIST));

	// Got Device List?
	if (nResult < 0){
		// Clean Up
		delete[] pRawInputDeviceList;

		// Error
		cout << "ERR: Could not get device list.";
		cin.get();
		return;
	}

	// Loop Through Device List
	for (UINT i = 0; i < nDevices; i++){
		// Get Character Count For Device Name
		UINT nBufferSize = 0;
		nResult = GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, // Device
			RIDI_DEVICENAME,                // Get Device Name
			NULL,                           // NO Buff, Want Count!
			&nBufferSize);                 // Char Count Here!

										   // Got Device Name?
		if (nResult < 0)
		{
			// Error
			cout << "ERR: Unable to get Device Name character count.. Moving to next device." << endl << endl;

			// Next
			continue;
		}

		// Allocate Memory For Device Name
		WCHAR* wcDeviceName = new WCHAR[nBufferSize + 1];

		// Got Memory
		if (wcDeviceName == NULL)
		{
			// Error
			cout << "ERR: Unable to allocate memory for Device Name.. Moving to next device." << endl << endl;

			// Next
			continue;
		}

		// Get Name
		nResult = GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice, // Device
			RIDI_DEVICENAME,                // Get Device Name
			wcDeviceName,                   // Get Name!
			&nBufferSize);                 // Char Count

										   // Got Device Name?
		if (nResult < 0)
		{
			// Error
			cout << "ERR: Unable to get Device Name.. Moving to next device." << endl << endl;

			// Clean Up
			delete[] wcDeviceName;

			// Next
			continue;
		}

		// Set Device Info & Buffer Size
		RID_DEVICE_INFO rdiDeviceInfo;
		rdiDeviceInfo.cbSize = sizeof(RID_DEVICE_INFO);
		nBufferSize = rdiDeviceInfo.cbSize;

		// Get Device Info
		nResult = GetRawInputDeviceInfo(pRawInputDeviceList[i].hDevice,
			RIDI_DEVICEINFO,
			&rdiDeviceInfo,
			&nBufferSize);

		// Got All Buffer?
		if (nResult < 0)
		{
			// Error
			cout << "ERR: Unable to read Device Info.. Moving to next device." << endl << endl;

			// Next
			continue;
		}

		printf("%u %u %u\n", rdiDeviceInfo.hid.dwVendorId, rdiDeviceInfo.hid.dwProductId, rdiDeviceInfo.hid.dwVersionNumber);

		// Delete Name Memory!
		delete[] wcDeviceName;
	}

	// Clean Up - Free Memory
	delete[] pRawInputDeviceList;

}
void networkInformationUnique() {
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char *mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return; // it is safe to call free(NULL)
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// technically should look at pAdapterInfo->AddressLength
			//   and not assume it is 6.
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			printf("%s %s\n", pAdapterInfo->IpAddressList.IpAddress.String, mac_addr);
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	free(mac_addr);
}
void systemInformationUnique() {
	SYSTEM_INFO siSysInfo;

	// Copy the hardware information to the SYSTEM_INFO structure. 

	GetSystemInfo(&siSysInfo);

	// Display the contents of the SYSTEM_INFO structure. 

	printf("  OEM ID: %u\n", siSysInfo.dwOemId);
	printf("  Number of processors: %u\n",siSysInfo.dwNumberOfProcessors);
	printf("  Page size: %u\n", siSysInfo.dwPageSize);
	printf("  Processor type: %u\n", siSysInfo.dwProcessorType);
	printf("  Minimum application address: %lx\n",siSysInfo.lpMinimumApplicationAddress);
	printf("  Maximum application address: %lx\n",siSysInfo.lpMaximumApplicationAddress);
	printf("  Active processor mask: %u\n",siSysInfo.dwActiveProcessorMask);
	printf("  Arch %lx\n", siSysInfo.wProcessorArchitecture);
}
void osInformationUnique() {
	WCHAR path[_MAX_PATH];
	if (!GetSystemDirectoryW(path, _MAX_PATH))
		return;
	//C:\WINDOWS\system32\drivers\rzpmgrk.sys
	wcscat_s(path, L"\\kernel32.dll");
	//wcscat_s(path, L"C:\WINDOWS\system32\drivers\rzpmgrk.sys");

	//
	// Based on example code from this article
	// http://support.microsoft.com/kb/167597
	//

	DWORD handle;
#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	DWORD len = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, path, &handle);
#else
	DWORD len = GetFileVersionInfoSizeW(path, &handle);
#endif
	if (!len)
		return;

	std::unique_ptr<uint8_t> buff(new (std::nothrow) uint8_t[len]);
	if (!buff)
		return;

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
	if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, path, 0, len, buff.get()))
#else
	if (!GetFileVersionInfoW(path, 0, len, buff.get()))
#endif
		return;

	VS_FIXEDFILEINFO *vInfo = nullptr;
	UINT infoSize;

	if (!VerQueryValueW(buff.get(), L"\\", reinterpret_cast<LPVOID*>(&vInfo), &infoSize))
		return;

	if (!infoSize)
		return;
	printf("Kernal version: %d.%d.%d.%d\n",
		(vInfo->dwFileVersionMS >> 16) & 0xffff,
		(vInfo->dwFileVersionMS >> 0) & 0xffff,
		(vInfo->dwFileVersionLS >> 16) & 0xffff,
		(vInfo->dwFileVersionLS >> 0) & 0xffff
	);
}
void cpuInformationUnique() {
	CPUID cpuID(0); // Get CPU vendor

	string vendor;
	vendor += string((const char *)&cpuID.EBX(), 4);
	vendor += string((const char *)&cpuID.EDX(), 4);
	vendor += string((const char *)&cpuID.ECX(), 4);
	cout << "CPU vendor = " << vendor << endl;
}
void driverInformationUnique() {
#define ARRAY_SIZE 1024
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;
	int cDrivers, i;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[ARRAY_SIZE];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		_tprintf(TEXT("There are %d drivers:\n"), cDrivers);
		for (i = 0; i < cDrivers; i++)
		{
			//GetDeviceDriverBaseName
			//GetDeviceDriverFileNameA
			if (GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				_tprintf(TEXT("%d: %s\n"), i + 1, szDriver);
			}
		}
	}
	else
	{
		_tprintf(TEXT("EnumDeviceDrivers failed; array size needed is %d\n"), cbNeeded / sizeof(LPVOID));
	}
}

// Main
int main() {
	installedProgramUnique();
	volumeInformationUnique();
	hardwareInformationUnique();
	networkInformationUnique();
	systemInformationUnique();
	osInformationUnique();
	cpuInformationUnique();
	driverInformationUnique();
	
	system("pause");
	return EXIT_SUCCESS;
}