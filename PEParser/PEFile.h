#pragma once
#include"windows.h"
#include"winnt.h"
#include<string>
#include<sstream>
#include<map>
#include<ctime>
#include<iomanip>
struct PEFile
{
	IMAGE_DOS_HEADER ImageDosHeader;
	ULONG Signature;
	IMAGE_FILE_HEADER ImageFileHeader;
	std::string GetImageDosHeaderAsString() {
		const char* Format = "Magic Number: [%hx, %c%c]\n"
			"Bytes on last page of file: [%hu] Bytes\n"
			"Pages in file: [%hu] pages\n"
			"Relocations: [%hu]\n"
			"Size of header in paragraphs: [%hu]\n"
			"Initial (relative) SS value: [%hu]\n"
			"Initial SP value: [%hu]\n"
			"Initial IP value: [%hu]\n"
			"Initial (relative) CS value: [%hu]\n"
			"File address of relocation table: [%hx]\n"
			"File address of new exe header: [%lx]\n";
		char Buffer[4096] = {};
		sprintf(Buffer, Format,
			ImageDosHeader.e_magic, (char)ImageDosHeader.e_magic, (char)(ImageDosHeader.e_magic >> 8),
			ImageDosHeader.e_cblp,
			ImageDosHeader.e_cp,
			ImageDosHeader.e_crlc,
			ImageDosHeader.e_cparhdr,
			ImageDosHeader.e_ss,
			ImageDosHeader.e_sp,
			ImageDosHeader.e_ip,
			ImageDosHeader.e_cs,
			ImageDosHeader.e_lfarlc,
			ImageDosHeader.e_lfanew
		);
		return std::string(Buffer);
	}
	std::string GetSignatureAsString() {
		const char* Format = "Signature: [%lx, %c%c]\n";
		char Buffer[32];
		sprintf(Buffer, Format, Signature, (char)Signature, (char)(Signature>>8), (char)(Signature>>16), (char)(Signature>>24));
		return std::string(Buffer);
	}
	const char* GetMachineTypeAsString() {
		static std::map<WORD, const char*> TypeMap = {
			{ IMAGE_FILE_MACHINE_UNKNOWN, "The contents of this field are assumed to be applicable to any machine type" },
			{ IMAGE_FILE_MACHINE_AM33, "Matsushita AM33" },
			{ IMAGE_FILE_MACHINE_AMD64, "x64" },
			{ IMAGE_FILE_MACHINE_ARM, "ARM little endian" },
			{ IMAGE_FILE_MACHINE_ARM64, "ARM64 little endian" },
			{ IMAGE_FILE_MACHINE_ARMNT, "ARM Thumb-2 little endian" },
			{ IMAGE_FILE_MACHINE_EBC, "EFI byte code" },
			{ IMAGE_FILE_MACHINE_I386, "Intel 386 or later processors and compatible processors" },
			{ IMAGE_FILE_MACHINE_IA64, "Intel Itanium processor family" },
			{ IMAGE_FILE_MACHINE_M32R, "Mitsubishi M32R little endian" },
			{ IMAGE_FILE_MACHINE_MIPS16, "MIPS16" },
			{ IMAGE_FILE_MACHINE_MIPSFPU, "MIPS with FPU" },
			{ IMAGE_FILE_MACHINE_MIPSFPU16, "MIPS16 with FPU" },
			{ IMAGE_FILE_MACHINE_POWERPC, "Power PC little endian" },
			{ IMAGE_FILE_MACHINE_POWERPCFP, "Power PC with floating point support" },
			{ IMAGE_FILE_MACHINE_R4000, "MIPS little endian" },
			//{ IMAGE_FILE_MACHINE_RISCV32, "RISC-V 32-bit address space" },
			//{ IMAGE_FILE_MACHINE_RISCV64, "RISC-V 64-bit address space" },
			//{ IMAGE_FILE_MACHINE_RISCV128, "RISC-V 128-bit address space" },
			{ IMAGE_FILE_MACHINE_SH3, "Hitachi SH3" },
			{ IMAGE_FILE_MACHINE_SH3DSP, "Hitachi SH3 DSP" },
			{ IMAGE_FILE_MACHINE_SH4, "Hitachi SH4" },
			{ IMAGE_FILE_MACHINE_SH5, "Hitachi SH5" },
			{ IMAGE_FILE_MACHINE_THUMB, "Thumb" },
			{ IMAGE_FILE_MACHINE_WCEMIPSV2, "MIPS little-endian WCE v2" },
		};

		auto Iter = TypeMap.find(ImageFileHeader.Machine);
		if (Iter == TypeMap.end()) {
			return "Unknown machine type.";
		}
		return (*Iter).second;
	}

	std::string GetCharacteristicsAsString() {
		static std::map<WORD, const char*> CharacteristicsMap = {
			{ IMAGE_FILE_RELOCS_STRIPPED, "Image only, Windows CE, and Microsoft Windows NT and later. This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address. If the base address is not available, the loader reports an error. The default behavior of the linker is to strip base relocations from executable (EXE) files." },
			{ IMAGE_FILE_EXECUTABLE_IMAGE, "Image only. This indicates that the image file is valid and can be run. If this flag is not set, it indicates a linker error." },
			{ IMAGE_FILE_LINE_NUMS_STRIPPED, "COFF line numbers have been removed. This flag is deprecated and should be zero." },
			{ IMAGE_FILE_LOCAL_SYMS_STRIPPED, "COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero." },
			//{ IMAGE_FILE_AGGRESSIVE_WS_TRIM, "Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero." },
			{ IMAGE_FILE_LARGE_ADDRESS_AWARE, "Application can handle > 2-GB addresses." },
			{ 0x0040, "This flag is reserved for future use." },
			{ IMAGE_FILE_BYTES_REVERSED_LO, "Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero." },
			{ IMAGE_FILE_32BIT_MACHINE, "Machine is based on a 32-bit-word architecture." },
			{ IMAGE_FILE_DEBUG_STRIPPED, "Debugging information is removed from the image file." },
			//{ IMAGE_FILE_REMOVABLE_RUN_ FROM_SWAP, "If the image is on removable media, fully load it and copy it to the swap file." },
			{ IMAGE_FILE_NET_RUN_FROM_SWAP, "If the image is on network media, fully load it and copy it to the swap file." },
			{ IMAGE_FILE_SYSTEM, "The image file is a system file, not a user program." },
			{ IMAGE_FILE_DLL, "The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run." },
			{ IMAGE_FILE_UP_SYSTEM_ONLY, "The file should be run only on a uniprocessor machine." },
			{ IMAGE_FILE_BYTES_REVERSED_HI, "Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero." },
		};

		std::stringstream Stream;
		Stream << "\n";
		auto Characteristics = ImageFileHeader.Characteristics;
		for (const auto& CharacteristicPair : CharacteristicsMap) {
			if (Characteristics & CharacteristicPair.first) {
				Stream << '\t' << CharacteristicPair.second << "\n";
			}
		}

		return Stream.str();
	}

	std::string GetTimeDateStampAsString() {
		std::time_t TimeStamp = (std::time_t)ImageFileHeader.TimeDateStamp;
		std::stringstream stream;
		stream << std::put_time(std::gmtime(&TimeStamp), "%Y-%m-%d %I:%M:%S %p");
		return stream.str();
	}

	std::string GetImageFileHeaderAsString() {
		const char* Format = "Machine: [%hu, %s]\n"
			"NumberOfSections: [%hu]\n"
			"TimeDateStamp: [%lu, %s]\n"
			"PointerToSymbolTable: [%lx]\n"
			"NumberOfSymbols: [%lu]\n"
			"SizeOfOptionalHeader: [%hu]\n"
			"Characteristics: [%hu, %s]\n";
		char Buffer[4096] = {};
		sprintf(Buffer, Format,
			ImageFileHeader.Machine, GetMachineTypeAsString(),
			ImageFileHeader.NumberOfSections,
			ImageFileHeader.TimeDateStamp, GetTimeDateStampAsString().c_str(),
			ImageFileHeader.PointerToSymbolTable,
			ImageFileHeader.NumberOfSymbols,
			ImageFileHeader.SizeOfOptionalHeader,
			ImageFileHeader.Characteristics, GetCharacteristicsAsString().c_str());
		return std::string(Buffer);
	}
};


