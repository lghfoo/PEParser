#pragma once
#include<iostream>
#include"windows.h"
#include"winnt.h"
#include"Logger.h"
#include"PEFile.h"
#include"PEFileDirect.h"
class PEParser
{
private:
	PEFile Result;
	PEFileDirect ResultDirect;
	void ParseImpl(FILE* File) {
		int EleRead = 0;
		// ImageDosHeader
		{
			EleRead = fread(&Result.ImageDosHeader, sizeof(Result.ImageDosHeader), 1, File);
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
				EleRead = fread(&Result.Signature, sizeof(Result.Signature), 1, File);
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
			EleRead = fread(&Result.ImageFileHeader, sizeof(Result.ImageFileHeader), 1, File);
			if (EleRead == 1) {
				Logger::Printlnf("================================ ImageFileHeader ================================");
				Logger::Printlnf(Result.GetImageFileHeaderAsString().c_str());
			}
			else {
				Logger::Printlnf("Failed to parse ImageFileHeader, [%d : %d]", EleRead, 1);
				return;
			}
		}

		// ImageOptionalHeader
		{
			// Magic: PE32 or PE32+?
			if (Result.HasImageOptionalHeader()) {
				EleRead = fread(&Result.OptionalHeaderMagic, sizeof(&Result.OptionalHeaderMagic), 1, File);
				if (EleRead == 1) {
					fseek(File, -((long)sizeof(&Result.OptionalHeaderMagic)), SEEK_CUR);
					Logger::Printlnf("================================ ImageOptionalHeader ================================");
					if (Result.IsPE32()) {
						EleRead = fread(&Result.ImageOptionalHeader.ImageOptionalHeader32,
							Result.GetSizeOfOptionalHeader(), 1, File);
						if (EleRead == 1) {
							Logger::Printlnf(Result.GetImageOptionalHeader32AsString().c_str());
						}
						else {
							Logger::Printlnf("Failed to read opt header32.");
							return;
						}
					}
					else if (Result.IsPE32Plus()) {
						EleRead = fread(&Result.ImageOptionalHeader.ImageOptionalHeader64,
							Result.GetSizeOfOptionalHeader(), 1, File);
						if (EleRead == 1) {
							Logger::Printlnf(Result.GetImageOptionalHeader64AsString().c_str());
						}
						else {
							Logger::Printlnf("Failed to read opt header64.");
							return;
						}
					}
					else {
						Logger::Printlnf("Failed to parse opt header, [unkown opt magic]");
						return;
					}
				}
				else {
					Logger::Printlnf("Failed to parse opt header, [opt magic]");
					return;
				}
			}
		}
	
		// Section Table (Section Headers)
		{
			auto NumOfSections = Result.GetNumberOfSections();
			auto& SectionTable = Result.SectionTable;
			SectionTable = new IMAGE_SECTION_HEADER[NumOfSections];
			EleRead = fread(SectionTable, sizeof(IMAGE_SECTION_HEADER), NumOfSections, File);
			if (EleRead == NumOfSections) {
				Logger::Printlnf("================================ Parse SectionTable ================================");
				Logger::Printlnf(Result.GetSectionTableAsString().c_str());
			}
			else {
				Logger::Printlnf("Failed to parse section table, [%d : %d]", EleRead, NumOfSections);
				return;
			}
		}
	}

	void DirectParseImpl(FILE* File) {
		fseek(File, 0, SEEK_END);
		long FileSize = ftell(File);
		fseek(File, 0, SEEK_SET);  
		ResultDirect.FileContent = new BYTE[FileSize];
		fread(ResultDirect.FileContent, sizeof(BYTE), FileSize, File);

		Logger::Printlnf("================================ ImageDosHeader ================================");
		Logger::Printlnf(ResultDirect.GetImageDosHeaderAsString().c_str());

		Logger::Printlnf("================================ Signature ================================");
		Logger::Printlnf(ResultDirect.GetSignatureAsString().c_str());

		Logger::Printlnf("================================ ImageFileHeader ================================");
		Logger::Printlnf(ResultDirect.GetImageFileHeaderAsString().c_str());

		if (ResultDirect.IsPE32()) {
			Logger::Printlnf("================================ ImageOptionalHeader32 ================================");
			Logger::Printlnf(ResultDirect.GetImageOptionalHeader32AsString().c_str());
		}
		else if(ResultDirect.IsPE32Plus()){
			Logger::Printlnf("================================ ImageOptionalHeader64 ================================");
			Logger::Printlnf(ResultDirect.GetImageOptionalHeader64AsString().c_str());
		}
		else {
			Logger::Printlnf("Unkown PE Foramt.");
		}

		delete[]ResultDirect.FileContent;
	}

public:
	void Parse(const char* File) {
		Logger::Printlnf("================================ PE Parser ================================");
		FILE* OpenedFile = fopen(File, "rb");
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
