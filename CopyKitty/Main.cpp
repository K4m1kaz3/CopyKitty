#pragma once
#include "FAT.h"
#include "NTFS.h"
#include<stdio.h>
#pragma warning (disable : 4996)
bool checkFormat(char volume) {
	char rootpath[] = "D:\\";
	rootpath[0] = volume;
	char volumenameBuffer[16];
	char fileSystemNameBuffer[16];
	DWORD serial, componentLength, flag;
	GetVolumeInformationA(rootpath, volumenameBuffer, 16, &serial, &componentLength, &flag, fileSystemNameBuffer, 16);
	if (strcmp(fileSystemNameBuffer, "NTFS") == 0) return TRUE;
	else return FALSE;
}
void GetInfo(wchar_t* file) {
	if (checkFormat(file[0])) {
		NTFS_GetFile(file);
	}
	else {
		char filename[256] = { 0 };
		wcstombs(filename, file, 256);
		FAT_GetFile(filename);
	}
}
void Copy(wchar_t* source, wchar_t* dest) {
	if (checkFormat(source[0])) {
		NTFS_CopyFile(source, dest);
	}
	else {
		char source_[256] = { 0 };
		wcstombs(source_, source, 256);
		char dest_[256] = { 0 };
		wcstombs(dest_, dest, 256);
		FAT_CopyFile(source_, dest_);
	}
}
int wmain(int argc, wchar_t** argv) {
	PVOID OldValue = NULL;
	if (Wow64DisableWow64FsRedirection(&OldValue) == 0) {
		printf("Calll Wow64DisableWow64FsRedirection failed! Error code: %d", GetLastError());
		return 1;
	}
	if (argc == 4 && wcscmp(argv[1], L"copy") == 0) {
		Copy(argv[2], argv[3]);
	}
	else if (argc == 3 && wcscmp(argv[1], L"fileinfo") == 0) {
		GetInfo(argv[2]);
	}
	else {
		printf("Description: \n\tThis tool is used to copy file in NTFS system. This tool can copy file even when file is locked by another process because directly read binary from hard disk\n");
		printf("Useage: \n");
		printf("\tCopyCat.exe copy [source] [dest]\t\t\t\tCopy file from [source] to [dest] folder\n");
		printf("\tCopyCat.exe fileinfo [filepath] \t\t\t\tGet file information, such as file size, file time, MFT time, owner, ... \n\n");
	}
}
// DirectVolumeAccess.exe fileinfo C:/Windows/System32/cmd.exe