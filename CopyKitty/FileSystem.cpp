#include "FileSystem.h"
#include<vector>
#pragma warning (disable : 4996)
Device* getDeviceInfo(char name) {
	char base[] = "\\\\.\\C:";
	Device* device = new Device;
	base[4] = name;
	HANDLE hDevice = CreateFileA(base, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	device->hDevice = hDevice;
	device->name = name;
	return device;
}
std::vector<char*> extract_filename(char* filename) {
	std::vector<char*> path;
	char* token = NULL;
	char* filename_copy = (char*)malloc(strlen(filename) + 1);
	strcpy(filename_copy, filename);
	token = strtok(filename_copy, "\\");
	while (token != NULL) {
		path.push_back(token);
		token = strtok(NULL, "\\");
	}
	return path;
}