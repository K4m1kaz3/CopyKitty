#include "NTFS.h"
#include<winternl.h>
#include<vector>
#include<atlstr.h>
#include<shlwapi.h>

#pragma comment (lib, "ntdll")
#pragma comment (lib, "shlwapi")
#pragma warning (disable : 4996)
void GetTimeFromMFT(SYSTEMTIME* systime, BYTE* MFT, int index) {
	FILETIME fileTime;
	memcpy(&fileTime, MFT + index, 8);
	FileTimeToSystemTime(&fileTime, systime);
}
void toLower(char* str, int length) {
	for (int i = 0; i < length; i++) {
		if ('A' <= str[i] && str[i] <= 'Z') {
			str[i] += 'a' - 'A';
		}
	}
}
std::vector<NonResidentCluster*>* extract_runlist(BYTE* runlist) {
	int run_number = 0;
	std::vector<NonResidentCluster*>* cluster = new std::vector<NonResidentCluster*>[1];
	BYTE* current_poniter = runlist;
	int oldoffset = 0;
	while (current_poniter[0] != 0) {
		int len_num = current_poniter[0] % 16;
		int offset_num = current_poniter[0] >> 4;
		int len = 0, offset = 0;
		for (int i = 0; i < len_num; i++) {
			len += (current_poniter[1 + i] << (8 * i));
		}
		for (int i = 0; i < offset_num; i++) {
			offset += (current_poniter[len_num + 1 + i] << (8 * i));
			if (i == offset_num - 1 && current_poniter[len_num + 1 + i] >= 0x80) {
				offset -= (1 << (8 * offset_num));
			}
		}
		NonResidentCluster* nonResidentCluster = (NonResidentCluster*)malloc(sizeof(NonResidentCluster));
		memset(nonResidentCluster, sizeof(NonResidentCluster), 0);
		nonResidentCluster->clusterIndex = offset + oldoffset;
		oldoffset = nonResidentCluster->clusterIndex;
		//		printf("Run %d : \n\tClusters %d @LCN %x\n", run_number + 1, len, oldoffset);
		nonResidentCluster->numberCluster = len;
		cluster->push_back(nonResidentCluster);
		current_poniter += (len_num + offset_num + 1);
	}
	return cluster;
}
NTFS_FILE* parseFile(BYTE* MFT, Device* device) {
	if (*(int*)MFT != 0x454c4946) return NULL;
	NTFS_FILE* file = new NTFS_FILE;
	memset(file, 0, sizeof(NTFS_FILE));
	LARGE_INTEGER currentPost;
	currentPost.QuadPart = 0;
	SetFilePointerEx(device->hDevice, currentPost, &file->distance, 1);
	file->distance.QuadPart -= 1024;
	file->LSN = *(long long*)(MFT + 8);
	file->hardLinkCount = MFT[0x12] + MFT[0x13] << 8;
	file->sequenceNumber = *(int*)(MFT + 0x2c);
	file->sequence = MFT[0x10] + (MFT[0x11] << 8);
	int att = (MFT[0x15] << 8) + MFT[0x14];
	int att_long = 0;
	file->device.hDevice = device->hDevice;
	file->device.name = device->name;
	if (att > 1024) {
		//		printf("Cannot found Attribute\n");
		return NULL;
	}
	while (*(MFT + att) != 0x10) {
		att_long = *(int*)(MFT + att + 4);
		if (att_long <= 0) {
			//			printf("Invalid long\n");
			return NULL;
		}
		att += att_long;
		if (att > 1024) {
			//			printf("Cannot found Attribute\n");
			return NULL;
		}
	}
	int precontentsize = MFT[att + 20] + (MFT[att + 21] << 8);
	file->USN = *(long long*)(MFT + att + precontentsize + 0x40);
	att_long = *(int*)(MFT + att + 4);
	if (att > 1024) {
		//		printf("Cannot found Attribute\n");
		return NULL;
	}
	while (*(MFT + att) != 0x30) {
		att_long = *(int*)(MFT + att + 4);
		if (att_long <= 0) {
			//			printf("Invalid long\n");
			return NULL;
		}
		att += att_long;
		if (att > 1024) {
			//			printf("Cannot found Attribute\n");
			return NULL;
		}
	}
	att_long = *(int*)(MFT + att + 4);
	if (att + att_long <= 1024)
		if (*(MFT + att + att_long) == 0x30) 
			att += att_long;
	precontentsize = MFT[att + 20] + (MFT[att + 21] << 8);
	file->ParentSequenceNumber = *(int*)(MFT + att + precontentsize);
	GetTimeFromMFT(&file->CreationTime, MFT, att + precontentsize + 8);
	GetTimeFromMFT(&file->ModificationTime, MFT, att + precontentsize + 16);
	GetTimeFromMFT(&file->AccessTime, MFT, att + precontentsize + 32);
	file->Flags = *(int*)(MFT + att + precontentsize + 0x38);
	wcsncpy_s(file->fileName, (wchar_t*)(MFT + att + precontentsize + 66), *(MFT + att + precontentsize + 64));
	if (att > 1024) {
		//		printf("Cannot found Attribute\n");
		return NULL;
	}
	while (*(MFT + att) != 0x80) {
		att_long = *(int*)(MFT + att + 4);
		if (att_long <= 0) {
			//			printf("Invalid long\n");
			return file;
		}
		att += att_long;
		if (att > 1024) {
			//			printf("Cannot found Attribute\n");
			return file;
		}
	}
	att_long = *(int*)(MFT + att + 4);
	if (MFT[att + 8] == 0) {
		file->fileSize = *(int*)(MFT + att + 0x10);
		file->nonResidentData = NULL;
	}
	else {
		if (att_long > 0x40) {
			file->fileSize = *(long long*)(MFT + att + 0x30);
			BYTE* runlist = &MFT[att + 0x40];
			file->nonResidentData = extract_runlist(runlist);
		}
		else if (att_long > 0x17) {
			file->fileSize = *(int*)(MFT + att + 0x10);
			BYTE* runlist = &MFT[att + 0x17];
			file->nonResidentData = extract_runlist(runlist);
		}
	}
	return file;
	return NULL;
}
NTFS_FILE* GetMFT(Device* device) {
	NTFS_BOOT* boot = GetNTFSDisk(device);
	LARGE_INTEGER distance;
	DWORD reader = 0;
	distance.QuadPart = boot->BytePerSec * boot->FirstMFTclust * boot->SecPerClust;
	SetFilePointerEx(device->hDevice, distance, NULL, 0);
	BYTE* MFT = new BYTE[MFT_SIZE];
	ReadFile(device->hDevice, MFT, MFT_SIZE, &reader, NULL);
	return parseFile(MFT, device);
}
void printFile(NTFS_FILE* file) {
	wprintf(L"File name : %ls\n", file->fileName);
	printf("Volume : %c\n", file->device.name);
	printf("Sequence number : %x\n", file->sequenceNumber);
	printf("Sequence : %d\n", file->sequence);
	printf("USN : %llx\n", file->USN);
	printf("Logfile sequence number : %llx\n", file->LSN);
	printf("Refernce : %d\n", file->hardLinkCount);
	printf("Parent directory entry: %llx\n", file->ParentSequenceNumber);
	printf("Flags : ");
	if ((file->Flags & 0x10000000) != 0) printf("Directory ");
	if ((file->Flags & 0x4) != 0) printf("System ");
	if ((file->Flags & 0x2) != 0) printf("Hidden ");
	if ((file->Flags & 0x1) != 0) printf("Read-Only ");
	if ((file->Flags & 0x20) != 0) printf("Archive ");
	if ((file->Flags & 0x800) != 0) printf("Compressed ");
	if ((file->Flags & 0x4000) != 0) printf("Encrypted ");
	printf("\n");
	if ((file->Flags & 0x10000000) == 0) {
		printf("File size : %lld\n", file->fileSize);
		if (file->nonResidentData != NULL) {
			for (int i = 0; i < file->nonResidentData->size(); i++)
				printf("Runlist %d: %d cluster at %x\n", i + 1, (file->nonResidentData->at(i))->numberCluster, (file->nonResidentData->at(i))->clusterIndex);
		}
	}
	printf("MFT Creation time : %4d-%02d-%02d %02d:%02d:%02d\n", file->CreationTime.wYear, file->CreationTime.wMonth
		, file->CreationTime.wDay, file->CreationTime.wHour, file->CreationTime.wMinute, file->CreationTime.wSecond);
	printf("MFT Last write time : %4d-%02d-%02d %02d:%02d:%02d\n", file->ModificationTime.wYear, file->ModificationTime.wMonth, file->ModificationTime.wDay,
		file->ModificationTime.wHour, file->ModificationTime.wMinute, file->ModificationTime.wSecond);
	printf("MFT Last access time : %4d-%02d-%02d %02d:%02d:%02d\n", file->AccessTime.wYear, file->AccessTime.wMonth, file->AccessTime.wDay,
		file->AccessTime.wHour, file->AccessTime.wMinute, file->AccessTime.wSecond);
}
NTFS_FILE* NTFS_GetFile(wchar_t* filename) {
	Device* device = getDeviceInfo(filename[0]);
	if (device == NULL) return NULL;
	NTFS_BOOT* boot = GetNTFSDisk(device);
	NTFS_FILE* MFT = GetMFT(device);
	NTFS_FILE* file = NULL;

	//older way(when I was young and stupid)
	/*
	DWORD reader = 0;
	std::vector<NTFS_FILE*> recheck_list;
	int reference_parent = 5;
	int count = 0;
	int counter = 0;
	std::vector<char*> name = extract_filename(filename);
	int foundflag = 0;
	char* current_name = new char[256];
	memset(current_name, 0, 256);
	for (int i = 0; i < MFT->nonResidentData->size(); i++) {
		NonResidentCluster* data = MFT->nonResidentData->at(i);
		LARGE_INTEGER distance;
		distance.QuadPart = data->clusterIndex * boot->BytePerSec * boot->SecPerClust;
		//printf("Data stream %d\n", i);
		SetFilePointerEx(device->hDevice, distance, NULL, 0);
		for (int j = 0; j < data->numberCluster * boot->SecPerClust * boot->BytePerSec / MFT_SIZE; j++) {
			BYTE* MFTdata = new BYTE[MFT_SIZE];
			memset(MFTdata, 0, MFT_SIZE);
			counter += 1;
			ReadFile(device->hDevice, MFTdata, MFT_SIZE, &reader, NULL);
			file = parseFile(MFTdata, device);
			if (file == NULL) {
				delete MFTdata;
				continue;
			}
			//				if (file->ParentSequenceNumber == 5) wprintf(L"%s\n", file->fileName);
			char* filename = new char[256];
			memset(filename, 0, 256);
			strcpy(filename, CW2A(file->fileName));
			toLower(filename, strlen(filename));

			for (int k = 0; k < name.size() - 1; k++) {

				if (strcmp(name.at(k + 1), filename) == 0) {
					if (file->ParentSequenceNumber == reference_parent) {
						reference_parent = file->sequenceNumber;
						count += 1;
						printf("-->%s\t%d\t%d\n", filename, file->sequenceNumber, file->ParentSequenceNumber);
						printf("Count:%d\n", counter);
						if (k == name.size() - 2) {
							foundflag = 1;
							printFile(file);
							break;
						}
						else
							memcpy(current_name, name.at(k + 2), 256);
					}
					else {
						NTFS_FILE* file_ = new NTFS_FILE;
						memcpy(file_, file, sizeof(NTFS_FILE));
						recheck_list.push_back(file_);
						//printf("%s\t%d\t%d\n", filename, file->sequenceNumber, file->ParentSequenceNumber);
					}
				}
			}
			memset(filename, 0, 256);
			delete filename;
			memset(MFTdata, 0, MFT_SIZE);
			delete MFTdata;
			if (foundflag == 1) break;
			memset(file, 0, sizeof(NTFS_FILE));
			delete file->nonResidentData;
			free(file);
		}
		if (foundflag == 1) break;
	}
	//duyet het mot vong
	if (foundflag == 0) {
		while (foundflag == 0) {
			int tick = 0;
			for (int i = 0; i < recheck_list.size(); i++) {
				file = recheck_list.at(i);
				char* filename = new char[256];
				memset(filename, 0, 256);
				strcpy(filename, CW2A(file->fileName));
				toLower(filename, strlen(filename));
				if (strcmp(current_name, filename) == 0 && reference_parent == file->ParentSequenceNumber) {
					tick = 1;
					reference_parent = file->sequenceNumber;
					count += 1;
					if (count == name.size() - 1) {
						printFile(file);
						foundflag = 1;
						free(filename);
						break;
					}
				}
				free(filename);
			}
			if (tick == 0) {
				printf("File not found!");
				return NULL;
			}
		}
	}
	*/
	//new way to found it!
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK status_block;
	HANDLE hFile = NULL;
	if (!PathFileExistsW(filename)) {
		printf("File not found!\n");
		return NULL;
	}

	wchar_t ntPath[256] = { 0 };
	wsprintf(ntPath, L"\\??\\%s", filename);
	UNICODE_STRING FileName;
	RtlInitUnicodeString(&FileName, ntPath);
	InitializeObjectAttributes(&attr, &FileName, OBJ_CASE_INSENSITIVE, 0, NULL);


	LONGLONG Status = NtOpenFile(&hFile, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &attr, &status_block, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
	if (Status != 0) { //open file success
		printf("Call NtOpenFile file! Error code: %x", Status);
		return NULL;
	}

	typedef NTSTATUS(WINAPI* _NtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, DWORD);
	_NtQueryInformationFile NtQueryInformationFile;
	IO_STATUS_BLOCK stat_block = { 0 };
	typedef struct _FILE_INTERNAL_INFORMATION {
		LARGE_INTEGER IndexNumber;
	} FILE_INTERNAL_INFORMATION, * PFILE_INTERNAL_INFORMATION;
	FILE_INTERNAL_INFORMATION fileInternal = { 0 };
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		printf("Cannot get ntdll module!. Error code: %d", GetLastError());
		return NULL;
	}
	NtQueryInformationFile = (_NtQueryInformationFile)GetProcAddress(ntdll, "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL) {
		printf("Cannot get NtQueryInformationFile function! Error code: %d.", GetLastError());
		return NULL;
	}
	//if (NtQueryInformationFile(hFile, &stat_block, &fileInfo, sizeof(FILE_BASIC_INFORMATION), 4) != 0) {
	if (NtQueryInformationFile(hFile, &stat_block, &fileInternal, sizeof(FILE_INTERNAL_INFORMATION), 6) != 0) {
		printf("Call NtQueryInformationFile function failed! Error code: %d.", GetLastError());
		return NULL;
	}
	DWORD sequence = fileInternal.IndexNumber.LowPart; //get MFT sequence number -> link to MFT record
	DWORD clusID = 0;
	for (clusID = 0; clusID < MFT->nonResidentData->size(); clusID++) {
		NonResidentCluster* data = MFT->nonResidentData->at(clusID);
		DWORD sectionPerCluster = data->numberCluster * boot->SecPerClust * boot->BytePerSec / MFT_SIZE;
		if (sequence < sectionPerCluster) break;
		sequence -= sectionPerCluster;
	}
	LARGE_INTEGER distance;
	distance.QuadPart = MFT->nonResidentData->at(clusID)->clusterIndex * boot->BytePerSec * boot->SecPerClust;
	distance.QuadPart += sequence * MFT_SIZE;
	SetFilePointerEx(device->hDevice, distance, NULL, 0); //jump to MFT entry =))) fucking complicated

	BYTE* MFTdata = new BYTE[MFT_SIZE];
	memset(MFTdata, 0, MFT_SIZE);
	DWORD reader = 0;
	ReadFile(device->hDevice, MFTdata, MFT_SIZE, &reader, NULL);
	file = parseFile(MFTdata, device);
	if (file == NULL) {
		printf("Parse file error!\n");
		return NULL;
	}
	printFile(file);
	return file;
}
BYTE* NTFS_ReadFile(NTFS_FILE *file, BYTE* buffer, int length, int run, int cluster) {
	DWORD reader = 0;
	if (file->nonResidentData == NULL) {
		SetFilePointerEx(file->device.hDevice, file->distance, NULL, 0);
		BYTE* thisMFT = new BYTE[MFT_SIZE];
		ReadFile(file->device.hDevice, buffer, length, &reader, NULL);
		int attribute_offset = thisMFT[0x14] + (thisMFT[0x15] << 8);
		int att_long = 0;
		while (thisMFT[attribute_offset] != 0x80) {
			att_long = *(int*)(thisMFT + attribute_offset + 4);
			if (att_long < 0) {
				printf("Cannot read file");
				return NULL;
			}
			if (attribute_offset + att_long > 1024) {
				printf("Cannot read file");
				return NULL;
			}
			attribute_offset += att_long;
		}
		int precontentsize = thisMFT[attribute_offset + 20] + (thisMFT[attribute_offset + 21] << 8);
		memcpy(buffer, &thisMFT[attribute_offset + precontentsize], length < file->fileSize ? length : file->fileSize);
		free(thisMFT);
	}
	else {
		NonResidentCluster* datarun = file->nonResidentData->at(run);
		LARGE_INTEGER distance;
		distance.QuadPart = 4096LL * (datarun->clusterIndex + cluster);
		if (SetFilePointerEx(file->device.hDevice, distance, NULL, 0) == FALSE) {
			printf("Cannot readfile");
			return NULL;
		}
		DWORD ByteCount;
		ReadFile(file->device.hDevice, buffer, 4096, &ByteCount, NULL);
	}
	return buffer;
}
void NTFS_CopyFile(wchar_t* sourceFile, wchar_t* destFolder) {

	NTFS_FILE* file = NTFS_GetFile(sourceFile);
	if (file == NULL) {
		printf("Cannot find this file");
		return;
	}
	wchar_t destFile[256] = { 0 };
	wcscpy(destFile, destFolder);
	wcscat(destFile, L"\\");
	wcscat(destFile, file->fileName);
	//replace this with CreateFileW/WriteFile
	HANDLE newFile = CreateFileW(destFile, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file->nonResidentData == NULL) {
		BYTE* buffer = (BYTE*)malloc(file->fileSize + 1);
		memset(buffer, 0, file->fileSize + 1);
		NTFS_ReadFile(file, buffer, file->fileSize, 0, 0);
		DWORD writer = 0;
		WriteFile(newFile, buffer, file->fileSize, &writer, NULL);
	}
	else {
		for (int i = 0; i < file->nonResidentData->size(); i++) {
			NonResidentCluster* datarun = file->nonResidentData->at(i);
			for (int j = 0; j < datarun->numberCluster; j++) {
				BYTE* buffer = (BYTE*)malloc(4096 + 1);
				memset(buffer, 0, 4096 + 1);
				NTFS_ReadFile(file, buffer, 4096, i, j);
				int numWrite = 4096;
				if (i == file->nonResidentData->size() - 1 && j == datarun->numberCluster - 1) numWrite = file->fileSize % 4096;
				DWORD writer = 0;
				WriteFile(newFile, buffer, numWrite, &writer, NULL);
			}
		}
	}
	CloseHandle(newFile);
	CloseHandle(file->device.hDevice);
}
NTFS_BOOT* GetNTFSDisk(Device* device) {
	BYTE* boot = new BYTE[512];
	DWORD reader = 0;
	SetFilePointer(device->hDevice, 0, NULL, 0);
	ReadFile(device->hDevice, boot, 512, &reader, 0);
	NTFS_BOOT* BootSector = new NTFS_BOOT;
	memset(BootSector, 0, sizeof(NTFS_BOOT));
	BootSector->FirstMFTclust = *(long long*)(boot + 0x30);
	BootSector->BytePerSec = boot[0xB] + (boot[0xC] << 8);
	BootSector->SecPerClust = boot[0xD];
	return BootSector;
}