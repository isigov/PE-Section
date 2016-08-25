#include "stdafx.h"
#include <Windows.h>

int Align(int Value, int Alignment);
void PE_Section_Add(char* filePath, char* sectionName, DWORD sectionSize);
LPVOID PE_Section_Read(char* filePath, char* sectionName);
void PE_Section_Clear(char* filePath, char* sectionName);
void PE_Section_Write(char* filePath, char* sectionName, char* data, DWORD dataLen);
void PE_Section_Delete(char* filePath, char* sectionName);

