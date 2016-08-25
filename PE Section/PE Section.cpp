#include "PE Section.h"

int Align(int Value, int Alignment)
{
	return((Value + Alignment) - (Value % Alignment));
}

void PE_Section_Add(char* filePath, char* sectionName, DWORD sectionSize)
{
	if(strlen(sectionName) > 7)
	{
		printf("error: section name is too long. max 8 characters\n");
		return;
	}

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == NULL)
	{
		printf("error: cannot open file\n");
		return;
	}

	DWORD dwRead = 0;
	DWORD fileSize = GetFileSize(filePath, NULL);
	DWORD fileSizeBackup = fileSize;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, dos_header, sizeof(IMAGE_DOS_HEADER), &dwRead, NULL);
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error: invalid dos header signature\n");
		return;
	}

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error: invalid nt header signature\n");
		return;
	}

	if(sectionSize < nt_headers->OptionalHeader.FileAlignment)
	{
		printf("error: section size cannot be smaller than file alignment\n");
		return;
	}

	IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers->FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i), NULL, FILE_BEGIN);
		ReadFile(hFile, &section_headers[i], sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);
		DWORD oldSize = section_headers[i].Misc.VirtualSize;
		section_headers[i].Misc.VirtualSize = Align(section_headers[i].Misc.VirtualSize, nt_headers->OptionalHeader.SectionAlignment);
	}
	//Properly align the VirtualSizes
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		if(i != nt_headers->FileHeader.NumberOfSections - 1)
		{
			if(section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize < section_headers[i + 1].VirtualAddress)
				section_headers[i].Misc.VirtualSize += section_headers[i + 1].VirtualAddress - (section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize);
			if(section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize > section_headers[i + 1].VirtualAddress)
				section_headers[i].Misc.VirtualSize -= (section_headers[i].VirtualAddress + section_headers[i].Misc.VirtualSize) - section_headers[i + 1].VirtualAddress;
		}
	}

	SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections), NULL, FILE_BEGIN);
	fileSize -= dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections);
	LPVOID fileBuffer = malloc(fileSize);
	ReadFile(hFile, fileBuffer, fileSize, &dwRead, NULL);

	DWORD EndOfSectionsVirtual = section_headers[nt_headers->FileHeader.NumberOfSections - 1].VirtualAddress + section_headers[nt_headers->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	DWORD EndOfSectionsRaw = section_headers[nt_headers->FileHeader.NumberOfSections - 1].PointerToRawData + section_headers[nt_headers->FileHeader.NumberOfSections - 1].SizeOfRawData;

	nt_headers->FileHeader.NumberOfSections++;

	IMAGE_SECTION_HEADER* newSect = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(newSect->Name, sectionName, sizeof(char) * strlen(sectionName));
	if(strlen(sectionName) < 8)
	{
		for(unsigned int i = strlen(sectionName); i < 8; i++)
		{
			newSect->Name[i] = 0;
		}
	}
	newSect->PointerToRawData = Align(EndOfSectionsVirtual, nt_headers->OptionalHeader.FileAlignment);
	newSect->SizeOfRawData = Align(sectionSize, nt_headers->OptionalHeader.FileAlignment);
	newSect->Misc.VirtualSize = Align(newSect->SizeOfRawData, nt_headers->OptionalHeader.SectionAlignment);
	newSect->VirtualAddress = Align(EndOfSectionsVirtual, nt_headers->OptionalHeader.SectionAlignment);
	newSect->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
	newSect->NumberOfLinenumbers = 00;
	newSect->NumberOfRelocations = 00;
	newSect->PointerToRelocations = 00;
	newSect->PointerToLinenumbers = 00;

	if(section_headers[nt_headers->FileHeader.NumberOfSections - 2].VirtualAddress + section_headers[nt_headers->FileHeader.NumberOfSections - 2].Misc.VirtualSize < newSect->VirtualAddress)
		section_headers[nt_headers->FileHeader.NumberOfSections - 2].Misc.VirtualSize += newSect->VirtualAddress - (section_headers[nt_headers->FileHeader.NumberOfSections - 2].VirtualAddress + section_headers[nt_headers->FileHeader.NumberOfSections - 2].Misc.VirtualSize);

	SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS), NULL, FILE_BEGIN);
	WriteFile(hFile, section_headers, sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1), &dwRead, NULL);

	SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1), NULL, FILE_BEGIN);
	WriteFile(hFile, newSect, sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);

	SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (nt_headers->FileHeader.NumberOfSections - 1) + sizeof(IMAGE_SECTION_HEADER), NULL, FILE_BEGIN);
	WriteFile(hFile, fileBuffer, fileSize, &dwRead, NULL);
	free(fileBuffer);

	fileSizeBackup = GetFileSize(hFile, NULL);

	newSect->Misc.VirtualSize = newSect->SizeOfRawData;
	if(newSect->VirtualAddress + newSect->Misc.VirtualSize > fileSizeBackup)
	{
		fileSizeBackup = (newSect->VirtualAddress + newSect->Misc.VirtualSize) - fileSizeBackup;
	}
	
	SetFilePointer(hFile, 0, NULL, FILE_END);
	LPVOID sectionBuffer = malloc(newSect->Misc.VirtualSize + fileSizeBackup);
	memset(sectionBuffer, 0, newSect->Misc.VirtualSize + fileSizeBackup);
	WriteFile(hFile, sectionBuffer, newSect->Misc.VirtualSize + fileSizeBackup, &dwRead, NULL);
	free(sectionBuffer);

	newSect->Misc.VirtualSize = Align(newSect->SizeOfRawData, nt_headers->OptionalHeader.SectionAlignment);
	nt_headers->OptionalHeader.SizeOfImage = newSect->VirtualAddress + newSect->Misc.VirtualSize;//+= Align(newSect->SizeOfRawData, nt_headers->OptionalHeader.SectionAlignment);// + addedBytes - removedBytes; //PE32 Loader doesn't recognize the ending data until it's initalized :(

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	WriteFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);

	CloseHandle(hFile);
}

LPVOID PE_Section_Read(char* filePath, char* sectionName)
{
	if(strlen(sectionName) > 7)
	{
		printf("error: section name is too long. max 8 characters\n");
		return NULL;
	}

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == NULL)
	{
		printf("error: cannot open file\n");
		return NULL;
	}

	DWORD dwRead = 0;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, dos_header, sizeof(IMAGE_DOS_HEADER), &dwRead, NULL);
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error: invalid dos header signature\n");
		return NULL;
	}

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error: invalid nt header signature\n");
		return NULL;
	}

	IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers->FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i), NULL, FILE_BEGIN);
		ReadFile(hFile, &section_headers[i], sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);

		char* sectNameBuffer = new char[8];
		memcpy(sectNameBuffer, section_headers[i].Name, 8);
		if(strstr(sectionName, sectNameBuffer))
		{
			LPVOID sectionBuffer = malloc(section_headers[i].SizeOfRawData);
			SetFilePointer(hFile, section_headers[i].PointerToRawData, NULL, FILE_BEGIN);
			ReadFile(hFile, sectionBuffer, section_headers[i].SizeOfRawData, &dwRead, NULL);
			CloseHandle(hFile);
			return sectionBuffer;
		}
	}

	return NULL;
}

void PE_Section_Clear(char* filePath, char* sectionName)
{
	if(strlen(sectionName) > 7)
	{
		printf("error: section name is too long. max 8 characters\n");
		return;
	}

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == NULL)
	{
		printf("error: cannot open file\n");
		return;
	}
	
	DWORD dwRead = 0;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, dos_header, sizeof(IMAGE_DOS_HEADER), &dwRead, NULL);
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error: invalid dos header signature\n");
		return;
	}

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error: invalid nt header signature\n");
		return;
	}

	IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers->FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i), NULL, FILE_BEGIN);
		ReadFile(hFile, &section_headers[i], sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);
		char* sectNameBuffer = new char[8];
		memcpy(sectNameBuffer, section_headers[i].Name, 8);
		if(strstr(sectionName, sectNameBuffer))
		{
			LPVOID randomData = malloc(section_headers[i].SizeOfRawData);
			memset(randomData, 0, section_headers[i].SizeOfRawData);
			SetFilePointer(hFile, section_headers[i].PointerToRawData, NULL, FILE_BEGIN);
			WriteFile(hFile, randomData, section_headers[i].SizeOfRawData, &dwRead, NULL);
			free(randomData);
			CloseHandle(hFile);
			return;
		}
	}
}

void PE_Section_Write(char* filePath, char* sectionName, char* data, DWORD dataLen)
{
	if(strlen(sectionName) > 7)
	{
		printf("error: section name is too long. max 8 characters\n");
		return;
	}

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == NULL)
	{
		printf("error: cannot open file\n");
		return;
	}
	
	DWORD dwRead = 0;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, dos_header, sizeof(IMAGE_DOS_HEADER), &dwRead, NULL);
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error: invalid dos header signature\n");
		return;
	}

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error: invalid nt header signature\n");
		return;
	}

	IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers->FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i), NULL, FILE_BEGIN);
		ReadFile(hFile, &section_headers[i], sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);
		char* sectNameBuffer = new char[8];
		memcpy(sectNameBuffer, section_headers[i].Name, 8);
		if(strstr(sectionName, sectNameBuffer))
		{
			LPVOID randomData = malloc(section_headers[i].SizeOfRawData);
			memset(randomData, 0, section_headers[i].SizeOfRawData);
			SetFilePointer(hFile, section_headers[i].PointerToRawData, NULL, FILE_BEGIN);
			WriteFile(hFile, randomData, section_headers[i].SizeOfRawData, &dwRead, NULL);
			free(randomData);
			SetFilePointer(hFile, section_headers[i].PointerToRawData, NULL, FILE_BEGIN);
			WriteFile(hFile, data, dataLen, &dwRead, NULL);
			CloseHandle(hFile);
			return;
		}
	}
}

void PE_Section_Delete(char* filePath, char* sectionName)
{
	if(strlen(sectionName) > 7)
	{
		printf("error: section name is too long. max 8 characters\n");
		return;
	}

	HANDLE hFile = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == NULL)
	{
		printf("error: cannot open file\n");
		return;
	}
	
	DWORD dwRead = 0;

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	ReadFile(hFile, dos_header, sizeof(IMAGE_DOS_HEADER), &dwRead, NULL);
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error: invalid dos header signature\n");
		return;
	}

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	ReadFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error: invalid nt header signature\n");
		return;
	}

	IMAGE_SECTION_HEADER* section_headers = new IMAGE_SECTION_HEADER[nt_headers->FileHeader.NumberOfSections];
	int curpos = -1;
	for(unsigned int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		SetFilePointer(hFile, dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i), NULL, FILE_BEGIN);
		ReadFile(hFile, &section_headers[i], sizeof(IMAGE_SECTION_HEADER), &dwRead, NULL);
		char* sectNameBuffer = new char[8];
		memcpy(sectNameBuffer, section_headers[i].Name, 8);
		if(strstr(sectionName, sectNameBuffer))
		{
			curpos = i;
			break;
		}
	}

	if(curpos < 0)
		return;

	nt_headers->FileHeader.NumberOfSections--;
	nt_headers->OptionalHeader.SizeOfImage -= section_headers[curpos].Misc.VirtualSize;

	DWORD fileSizeBuffer = section_headers[curpos].VirtualAddress + section_headers[curpos].Misc.VirtualSize;
	LPVOID fileBuffer = malloc((GetFileSize(hFile, NULL) - section_headers[curpos].SizeOfRawData) - fileSizeBuffer);

	SetFilePointer(hFile, fileSizeBuffer, NULL, FILE_BEGIN);
	ReadFile(hFile, fileBuffer, (GetFileSize(hFile, NULL) - section_headers[curpos].SizeOfRawData), &dwRead, NULL);

	SetFilePointer(hFile, dos_header->e_lfanew, NULL, FILE_BEGIN);
	WriteFile(hFile, nt_headers, sizeof(IMAGE_NT_HEADERS), &dwRead, NULL);

	SetFilePointer(hFile, section_headers[curpos - 1].VirtualAddress + section_headers[curpos - 1].Misc.VirtualSize, NULL, FILE_BEGIN);
	WriteFile(hFile, fileBuffer, (GetFileSize(hFile, NULL) - section_headers[curpos].SizeOfRawData), &dwRead, NULL);

	free(fileBuffer);
	CloseHandle(hFile);
}