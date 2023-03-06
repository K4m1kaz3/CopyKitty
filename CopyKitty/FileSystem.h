#pragma once
#include<Windows.h>
#include<vector>
typedef struct Device {
	HANDLE hDevice;
	char name;
}Device;
Device* getDeviceInfo(char name);
std::vector<char*> extract_filename(char* filename);