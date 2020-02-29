#pragma once
#include<iostream>
#include"windows.h"
#include"winnt.h"
#include"Logger.h"
#include"PEFile.h"
class PEParser
{
private:
	PEFile Result;
	void ParseImpl(FILE* File) {
		int EleRead = 0;
		// ImageDosHeader
		{
			EleRead = fread((void*)&Result.ImageDosHeader, sizeof(Result.ImageDosHeader), 1, File);
			if (EleRead == 1) {
				Logger::Printlnf("================================ ImageDosHeader ================================");
				Logger::Printlnf(Result.GetImageDosHeaderAsString().c_str());
			}
			else {
				Logger::Printlnf("Failed to parse ImageDosHeader, [%d : %d]", EleRead, 1);
				return;
			}
		}

		// Signature
		{
			if (fseek(File, Result.ImageDosHeader.e_lfanew, SEEK_SET) == 0) {
				EleRead = fread((void*)&Result.Signature, sizeof(Result.Signature), 1, File);
				if (EleRead == 1) {
					Logger::Printlnf("================================ Signature ================================");
					Logger::Printlnf(Result.GetSignatureAsString().c_str());
				}
				else {
					Logger::Printlnf("Failed to parse Signature, [%d : %d]", EleRead, 1);
					return;
				}
			}
			else {
				Logger::Printlnf("Failed to parse Signature, [fail to seek]");
				return;
			}
		}


		// ImageFileHeader
		{
			EleRead = fread((void*)&Result.ImageFileHeader, sizeof(Result.ImageFileHeader), 1, File);
			if (EleRead == 1) {
				Logger::Printlnf("================================ ImageFileHeader ================================");
				Logger::Printlnf(Result.GetImageFileHeaderAsString().c_str());
			}
			else {
				Logger::Printlnf("Failed to parse ImageFileHeader, [%d : %d]", EleRead, 1);
				return;
			}
		}
	}


public:
	void Parse(const char* File) {
		Logger::Printlnf("================================ PE Parser ================================");
		FILE* OpenedFile = fopen(File, "r");
		if (OpenedFile) {
			Logger::Printlnf("Parse %s", File);
			ParseImpl(OpenedFile);
			fclose(OpenedFile);
		}
		else {
			Logger::Printlnf("Failed to open '%s'", File);
		}
	}
};
