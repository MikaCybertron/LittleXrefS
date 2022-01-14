#include <Windows.h>
#include <iostream>
#include "LittleXrefs.h"
#include <conio.h>

struct insn_off_ocurrence {
	std::string insn;
	uintptr_t offset;
};

struct func_off_ocurences_info{
	std::string func_name;
	uintptr_t	func_offset;
	std::vector<insn_off_ocurrence> offset_ocurrences;
};

std::vector<func_off_ocurences_info> offset_usage_functions_in;

bool reg_present_in_current_insn(const cs_insn* insn, arm_reg reg)
{
	for (int i = 0; i < insn->detail->arm.op_count; i++)
	{
		if (insn->detail->arm.operands[i].reg == reg)
			return true;
	}

	return false;
}

bool is_func_end(const cs_insn* insn)
{
	if (insn->id == arm_insn::ARM_INS_BX)
	{
		if (reg_present_in_current_insn(insn, arm_reg::ARM_REG_LR))
			return true;
	}
	else if (insn->id == arm_insn::ARM_INS_POP)
	{
		if (reg_present_in_current_insn(insn, arm_reg::ARM_REG_PC))
			return true;
	}

	return false;
}

arm_reg get_insn_lvalue_reg_type(cs_insn* insn)
{
	return (arm_reg)insn->detail->arm.operands[0].reg;
}

arm_reg get_insn_rvalue_reg_type(cs_insn* insn)
{
	return (arm_reg)insn->detail->arm.operands[1].reg;
}

bool find_reg_off_usage(cs_insn* disasm_opcodes, uintptr_t num_insn, uintptr_t to_find_offset, func_off_ocurences_info* fooi, arm_reg reg_focus = arm_reg::ARM_REG_R0, uintptr_t curr_insn_index = 0)
{
	bool ocurrences_found = false;

	for (int i = curr_insn_index; i < num_insn; i++)
	{
		cs_insn* curr_insn = disasm_opcodes + i;

		//printf("%s %s\n", curr_insn->mnemonic, curr_insn->op_str);

		if (is_func_end(curr_insn))
			return ocurrences_found;

		if (reg_present_in_current_insn(curr_insn, reg_focus))
		{
			switch (curr_insn->id)
			{

			case arm_insn::ARM_INS_MOV:
				if (get_insn_rvalue_reg_type(curr_insn) == reg_focus) // verify if reg_focus is getting copied
				{
					//if so then recurse in copy register
					if (find_reg_off_usage(disasm_opcodes, num_insn, to_find_offset, fooi, get_insn_lvalue_reg_type(curr_insn), i + 1))
						ocurrences_found = true;
				}
				else {
					return ocurrences_found;
				}
				break;

			case arm_insn::ARM_INS_LDR:
			case arm_insn::ARM_INS_LDRB:
			case arm_insn::ARM_INS_STR:
			case arm_insn::ARM_INS_STRB:
				return ocurrences_found;
			}
		}
		else {
			switch (curr_insn->id)
			{

			case arm_insn::ARM_INS_LDR:
			case arm_insn::ARM_INS_LDRB:
			case arm_insn::ARM_INS_STR:
			case arm_insn::ARM_INS_STRB:
				if (curr_insn->detail->arm.operands[1].mem.base == reg_focus)
				{
					if (curr_insn->detail->arm.operands[1].mem.disp == to_find_offset)
					{
						insn_off_ocurrence ioo;
						char full_insn[64];

						ocurrences_found = true;
						sprintf_s(full_insn, "%s %s", curr_insn->mnemonic, curr_insn->op_str);
						ioo.insn = std::string(full_insn);
						ioo.offset = curr_insn->address;
						fooi->offset_ocurrences.push_back(ioo);
					}
						
				}
				break;
			}
		}
	}

	return ocurrences_found;
}

const char* GetParentesisStart(const char* str)
{
	const char* result = str;

	while (*result != '(') result++;

	return result;
}

// going backwards from the ocurrence to the reverse start and counting commas
int ReverseCommaCount(const char* reverse_start, const char* reverse_end)
{
	int result = 0;
	const char* tmpstr = reverse_end;

	while (tmpstr >= reverse_start)
	{
		if(*tmpstr == ',')
			result++;

		tmpstr--;
	}

	return result;
}

int main()
{
	if (LX::Init() != LX::LX_OK)
	{
		printf("Error while initializing LittleXrefs\n");
		exit(1);
	}

	cs_insn*		disasm_opcodes;
	uintptr_t		n_disasm_opcodes = 0;
	char			class_name_str[256];
	char			class_name_str_mask[256];
	uintptr_t		offset = 0;
	unsigned char*	il2cpp_buff = LX::g_pLXrefs->getAssemblyEntry();
	Json::Value&	il2cpp_json_obj = LX::g_pLXrefs->getDumpJsonObj();
	csh&			cs_h = LX::g_pLXrefs->getCSHandle();
	

	while (true)
	{
		std::cout << "Type Class Name: ";	std::cin >> class_name_str;
		std::cout << "Type Offset: ";		std::cin >> std::hex >> offset;
		sprintf_s(class_name_str_mask, "%s_o*", class_name_str);
		auto& script_methods = il2cpp_json_obj["ScriptMethod"];

		for (uintptr_t i = 0; i < script_methods.size(); i++)
		{
			auto& curr_script_method = script_methods[i];
			const char* param_parentesis_start = GetParentesisStart(curr_script_method["Signature"].asCString());
			const char* result = nullptr;

			if (result = strstr(param_parentesis_start, class_name_str_mask))
			{
				int comma_counts = ReverseCommaCount(param_parentesis_start, result);
				func_off_ocurences_info curr_func_ocurrences;
				uintptr_t curr_func_off = curr_script_method["Address"].asUInt();

				n_disasm_opcodes = cs_disasm(cs_h, il2cpp_buff + curr_func_off, 0x2000, NULL, NULL, &disasm_opcodes);

				if (n_disasm_opcodes != 0)
				{
					if (find_reg_off_usage(disasm_opcodes, n_disasm_opcodes, offset, &curr_func_ocurrences, (arm_reg)(arm_reg::ARM_REG_R0 + comma_counts)))
					{
						curr_func_ocurrences.func_name = std::string(curr_script_method["Name"].asCString());
						curr_func_ocurrences.func_offset = curr_func_off;
						offset_usage_functions_in.push_back(curr_func_ocurrences);
					}
				}

				cs_free(disasm_opcodes, n_disasm_opcodes);
			}
		}

		for (int i = 0; i < offset_usage_functions_in.size(); i++)
		{
			auto& curr_function_info = offset_usage_functions_in[i];

			printf("%s\n", curr_function_info.func_name.c_str());

			for (int j = 0; j < curr_function_info.offset_ocurrences.size(); j++)
			{
				auto& curr_insn_off_ocurr_info = curr_function_info.offset_ocurrences[j];
				printf("  \"%s\" => [%08X]\n", curr_insn_off_ocurr_info.insn.c_str(), curr_function_info.func_offset + curr_insn_off_ocurr_info.offset);
			}

			printf("\n");
		}

		_getch();
		system("cls");

		ZeroMemory(class_name_str, 256);
		ZeroMemory(class_name_str_mask, 256);
		offset_usage_functions_in.clear();
	}
}