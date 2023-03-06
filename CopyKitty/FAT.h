#pragma once
#include "FileSystem.h"
typedef struct FAT_FILE {
	char* fileName;
	int attribute;
	WORD creationTime;
	WORD creationDate;
	WORD accessDate;
	DWORD fileSize;
	DWORD clust_number;
	LARGE_INTEGER distance;
}FAT_FILE;
typedef struct FAT_BOOT {
	int BytePerSec;
	int SecPerClust;
	int FAT_number;
	int FAT_sector;
	int ReverseSector;
	int firstRootclust;
}FAT_BOOT;
typedef struct FAT_DIR {

}FAT_DIR;
FAT_FILE* FAT_GetFile(char* filename);
void FAT_CopyFile(char* sourceFile, char* destFile);
void FAT_RemoveFile(char* filename);
FAT_BOOT* GetFatDisk(Device* device);