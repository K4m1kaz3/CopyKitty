#pragma once
#include "FileSystem.h"
#include<vector>
#define MFT_SIZE 1024
typedef struct NonResidentCluster {
	long long clusterIndex;
	int numberCluster;
}NonResidentCluster;
typedef struct NTFS_BOOT {
	int BytePerSec;
	int SecPerClust;
	long long FirstMFTclust;
}NTFS_BOOT;
typedef struct NTFS_FILE {
	int sequenceNumber;
	long long USN;
	int sequence;
	wchar_t fileName[256];
	long long LSN;
	int hardLinkCount;
	SYSTEMTIME CreationTime, ModificationTime, AccessTime;
	int Flags;
	int ParentSequenceNumber;
	long long fileSize;
	std::vector<NonResidentCluster*>* nonResidentData;
	Device device;
	LARGE_INTEGER distance;
}NTFS_FILE;
NTFS_FILE* NTFS_GetFile(wchar_t* MFT);
BYTE* NTFS_ReadFile(NTFS_FILE* file, BYTE* buffer, int length, int run, int cluster);
void NTFS_CopyFile(wchar_t* sourceFile, wchar_t* destFolder);
NTFS_BOOT* GetNTFSDisk(Device* device);