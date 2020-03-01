// References:
// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
// https://blog.kowalczyk.info/articles/pefileformat.html

#include<iostream>
#include"PEParser.h"
int main(int argc, char* argv[]) {
	PEParser Parser;
	//Parser.Parse("D:\\Software\\Unreal\\UnrealEngine-release\\Engine\\Binaries\\Win64\\ShaderConductor.dll");
	Parser.Parse("D:\\Software\\Unreal\\UnrealEngine-release\\Engine\\Binaries\\Win64\\UE4Editor.exe");
	//Parser.Parse("D:\\Software\\Steam\\steamapps\\common\\Hollow Knight\\hollow_knight.exe");
	//Parser.Parse("D:\\Software\\Steam\\steamapps\\common\\Hollow Knight\\UnityPlayer.dll");
	//Parser.Parse("D:\\Software\\Steam\\steamapps\\common\\Hollow Knight\\hollow_knight_Data\\Plugins\\CSteamworks.dll");
	//Parser.Parse("D:\\Software\\Steam\\steamapps\\common\\Hollow Knight\\hollow_knight_Data\\Plugins\\steam_api.dll");
}