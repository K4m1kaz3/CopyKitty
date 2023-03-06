#include "FAT.h"
#pragma warning (disable : 4996)
void printFile(FAT_FILE* file);
void unpackTime(WORD time);
void unpackDate(WORD date);
FAT_FILE* getFile(BYTE* fat, HANDLE hDevice, FAT_BOOT* boot) {
	char* longname = (char*)malloc(256);
	memset(longname, 0, 256);
	FAT_FILE* file = new FAT_FILE;
	while (fat[0xb] == 0xf) {
		char* sub_sort_name = new char[256];
		memset(sub_sort_name, 0, 256);
		for (int k = 0; k < 5; k++) sub_sort_name[k] = fat[2 * k + 1];
		for (int k = 0; k < 6; k++) sub_sort_name[k + 5] = fat[2 * k + 0xe];
		sub_sort_name[11] = fat[28];
		sub_sort_name[12] = fat[30];
		strcat(sub_sort_name, longname);
		strcpy(longname, sub_sort_name);
		fat += 32;
	}
	file->fileName = (char*)malloc(256);
	if (file->fileName == NULL) return NULL;
	memset(file->fileName, 0, 256);
	if (strlen(longname) > 0) {
		strcpy(file->fileName, longname);
		memset(longname, 0, 256);
	}
	else {
		if (fat[0xb] & 8 || fat[0xb] & 16) {
			strncpy(file->fileName, (char*)fat, 11);
			int i = strlen(file->fileName);
			while (file->fileName[i - 1] == ' ') {
				file->fileName[i - 1] = '\x00';
				i -= 1;
			}
		}
		else {
			int count = 0;
			char filename[13] = { 0 };
			while (fat[count] != ' ' && count < 8) {
				filename[count] = fat[count];
				count += 1;
			}
			filename[count] = '.';
			count = 8;
			while (fat[count] != ' ' && count < 11) {
				filename[strlen(filename)] = fat[count];
				count += 1;
			}
			strcpy(file->fileName, filename);
			if (strlen(filename) == 0) return NULL;
		}
	}
	LARGE_INTEGER distance;
	distance.QuadPart = 0;
	SetFilePointerEx(hDevice, distance, &file->distance, 1);
	file->distance.QuadPart -= boot->BytePerSec;
	file->attribute = fat[0xb];
	file->accessDate = fat[0x12] + (fat[0x13] << 8);
	file->clust_number = fat[0x1a] + (fat[0x1b] << 8);
	file->creationDate = fat[0x10] + (fat[0x11] << 8);
	file->creationTime = fat[0xe] + (fat[0xf] << 8);
	file->fileSize = *(int*)(fat + 0x1c);
	if (file->fileSize < 0) return NULL;
	return file;
}
char* ToLow(char* string) {
	char* ret_str = new char[strlen(string) + 1];
	memset(ret_str, 0, strlen(string) + 1);
	for (int i = 0; i < strlen(string); i++) {
		if (string[i] >= 'A' && string[i] <= 'Z') ret_str[i] = string[i] + ('a' - 'A');
		else ret_str[i] = string[i];
	}
	return ret_str;
}
FAT_FILE* FAT_GetFile(char* filename) {
	std::vector<char*> name = extract_filename(filename);
	Device* device = getDeviceInfo(filename[0]);
	FAT_BOOT* boot = GetFatDisk(device);
	FAT_FILE* file = NULL;
	long long baseCluster = boot->firstRootclust;
	for (int i = 0; i < name.size() - 1; i++) {
		LARGE_INTEGER distance;
		distance.QuadPart = 512LL * (boot->ReverseSector + boot->FAT_number * boot->FAT_sector + (baseCluster - 2) * boot->SecPerClust);
		if (SetFilePointerEx(device->hDevice, distance, NULL, 0));
		BYTE* sector = new BYTE[boot->BytePerSec];
		int endflag = 0, foundflag = 0;
		while (TRUE) {
			ReadFile(device->hDevice, sector, boot->BytePerSec, NULL, NULL);
			BYTE* currentRead = sector;
			while (currentRead < sector + boot->BytePerSec) {
				file = getFile(currentRead, device->hDevice, boot);
				if (file == NULL) {
					endflag = 1;
					break;
				}
				else if (strcmp(ToLow(file->fileName), ToLow(name.at(i + 1))) == 0) {
					foundflag = 1;
					break;
				}
				while (currentRead[0xb] == 0xf) currentRead += 32;
				currentRead += 32;
			}
			if (endflag == 1 || foundflag == 1) break;
		}
		if (endflag) {
			CloseHandle(device->hDevice);
			return NULL;
		}
		else if (foundflag) {
			baseCluster = file->clust_number;
		}
	}
	printFile(file);
	CloseHandle(device->hDevice);
	return file;
}
void unpackTime(WORD time) {
	printf("%d : %d", (time >> 11), (time >> 5) & 0b111111);
}
void unpackDate(WORD date) {
	printf("%d / %d / %d", (1980 + (date >> 9)), (date >> 5) & 0b1111, date & 0b11111);
}
void printFile(FAT_FILE* file) {
	if (file == NULL) return;
	printf("File name : %s\n", file->fileName);
	printf("File size : %d\n", file->fileSize);
	printf("File attribute : ");
	if (file->attribute & 1) printf("write protect, ");
	if (file->attribute & 2) printf("hidden, ");
	if (file->attribute & 4) printf("system, ");
	if (file->attribute & 8) printf("volume, ");
	if (file->attribute & 16) printf("directory, ");
	if (file->attribute & 32) printf("archive, ");
	printf("\n");
	printf("First clust : %x\n", file->clust_number);
	printf("Creation date : "); unpackDate(file->creationDate);
	printf("\nCreation time : "); unpackTime(file->creationTime);
	printf("\nAccess date : "); unpackDate(file->accessDate);
	printf("\n------------------\n");
}
void FAT_CopyFile(char* sourceFile, char* destFile) {
	FAT_FILE* file = FAT_GetFile(sourceFile);
	Device* device = getDeviceInfo(sourceFile[0]);
	FAT_BOOT* boot = GetFatDisk(device);
	BYTE* buffer = new BYTE[boot->BytePerSec];
	memset(buffer, 0, boot->BytePerSec);
	LARGE_INTEGER distance;
	distance.QuadPart = boot->BytePerSec * (boot->ReverseSector + boot->FAT_number * boot->FAT_sector + (file->clust_number - 2) * boot->SecPerClust);
	SetFilePointerEx(device->hDevice, distance, NULL, 0);
	int current_read = 0;
	HANDLE newfile = CreateFileA(destFile, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS, 0, NULL);
	while (TRUE) {
		int read = (file->fileSize - current_read < boot->BytePerSec ? file->fileSize - current_read : boot->BytePerSec);
		ReadFile(device->hDevice, buffer, boot->BytePerSec, NULL, NULL);
		WriteFile(newfile, buffer, read, NULL, NULL);
		current_read += read;
		memset(buffer, 0, boot->BytePerSec);
		if (current_read >= file->fileSize) {
			CloseHandle(newfile);
			CloseHandle(device->hDevice);
			break;
		}
	}
}
void FAT_RemoveFile(char* filename) {
	FAT_FILE* file = FAT_GetFile(filename);
	if (file == NULL) return;
	Device* device = getDeviceInfo('F');
	FAT_BOOT* boot = GetFatDisk(device);
	LARGE_INTEGER distance;
	distance.QuadPart = boot->BytePerSec * (boot->ReverseSector + boot->FAT_number * boot->FAT_sector +
		(file->clust_number - 2) * boot->SecPerClust);
	if (SetFilePointerEx(device->hDevice, distance, NULL, 0) == FALSE) {
		printf("Cannot set pointer, error code : %d \n", GetLastError());
	}
	int size = (boot->BytePerSec) * ((file->fileSize + (boot->BytePerSec - 1)) / (boot->BytePerSec));
	char* memclear = new char[size];
	memset(memclear, 0, size);
	DWORD byteReturn;
	if (DeviceIoControl(device->hDevice, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &byteReturn, NULL) == 0) {
		printf("Error : %d", GetLastError());
	} 
	WriteFile(device->hDevice, memclear, size, NULL, NULL);
	//jump to sector contain this file 
	SetFilePointerEx(device->hDevice, file->distance, NULL, 0);
	BYTE* buffer = new BYTE[boot->BytePerSec];

	FAT_FILE* newfile = NULL;
	int endflag = 0, foundflag = 0;
	BYTE* sector = new BYTE[boot->BytePerSec];
	BYTE* currentRead = sector;
	BYTE* lastFile = sector;
	while (TRUE) {
		ReadFile(device->hDevice, sector, boot->BytePerSec, NULL, NULL);
		while (currentRead < sector + boot->BytePerSec) {
			lastFile = currentRead;
			newfile = getFile(currentRead, device->hDevice, boot);
			while (currentRead[0xb] == 0xf) currentRead += 32;
			currentRead += 32;
			if (newfile == NULL) {
				endflag = 1;
				break;
			}
			else if (strcmp(ToLow(newfile->fileName), ToLow(file->fileName)) == 0) {
				foundflag = 1;
				break;
			}
		}
		if (endflag == 1 || foundflag == 1) break;
	}
	memset(lastFile, 0, currentRead - lastFile);
	distance.QuadPart = -boot->BytePerSec;
	SetFilePointerEx(device->hDevice, distance, NULL, 1);
	WriteFile(device->hDevice, sector, boot->BytePerSec, NULL, NULL);
//	DeviceIoControl(device->hDevice, FSCTL_MOUNT, NULL, 0, NULL, 0, &byteReturn, NULL);
}
FAT_BOOT* GetFatDisk(Device* device) {
	BYTE* boot = new BYTE[512];
	ReadFile(device->hDevice, boot, 512, NULL, 0);
	FAT_BOOT* BootSector = new FAT_BOOT;
	memset(BootSector, 0, sizeof(FAT_BOOT));
	BootSector->BytePerSec = boot[0xb] + (boot[0xc] << 8);
	BootSector->FAT_number = boot[0x10] + (boot[0x11] << 8);
	BootSector->ReverseSector = boot[0xe] + (boot[0xf] << 8);
	BootSector->firstRootclust = *(int*)(boot + 0x2c);
	BootSector->SecPerClust = boot[0xd];
	BootSector->FAT_sector = *(int*)(boot + 0x24);
	return BootSector;
}