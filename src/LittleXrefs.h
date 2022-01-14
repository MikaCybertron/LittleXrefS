#pragma once
#include <string>
#include <json\json.h>
#include <capstone\capstone.h>
#include <fstream>

namespace LX{

	#define LXFILE_MODE_IN std::ios::in
	#define LXFILE_MODE_IN_BINARY std::ios::in | std::ios::ate | std::ios::binary

	enum LXERROR
	{
		LX_OK,
		LX_FILESLOAD,
		LX_DISASM
	};

	LXERROR Init();

	class LittleXrefs {
	private:
		unsigned char*	m_AssemblyBuffEntry;
		Json::Value		m_ScriptJsonObj;
		csh				m_CapstoneDisasm;

	public:
		LittleXrefs();
		~LittleXrefs();
		bool LoadFiles();
		bool InitDisasm();
		Json::Value&	getDumpJsonObj();
		unsigned char*	getAssemblyEntry();
		csh&			getCSHandle();
	};

	namespace Utils {
		bool get_assembly_path(std::wstring& out_path);
		bool get_script_path(std::wstring& out_path);
		bool cstr_to_json_obj(const char* json_char_buff, Json::Value& json_obj);

		class LXFile {
		private:
			std::fstream* m_FileStream;

		public:
			LXFile();
			LXFile(const std::wstring& path, uintptr_t mode);
			~LXFile();

			bool isOpen();
			size_t getFileSize();
			bool ReadFile(void* buff, uintptr_t buffSize);
		};
	}

	extern LittleXrefs* g_pLXrefs;
}

