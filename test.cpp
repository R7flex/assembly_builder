#include <iostream>
#include <iomanip>
#include <windows.h>

#include "assembly_builder.hpp"
using namespace shellcode;

void example_function() {
    std::cout << "huso niye facebook oldun" << std::endl;
}

int32_t main() {
    {
        shellcode::assemby_builder builder;

        builder
            .add(assembly_instruction::x64_type::MOV, { assembly_instruction::x64_register::RAX, &example_function })
            .add(assembly_instruction::x64_type::CALL, { assembly_instruction::x64_register::RAX })
            .add(assembly_instruction::x64_type::RET);

        auto shellcode = builder.build();

        std::cout << "generated func shell:" << std::endl;
        for (auto byte : shellcode) {
            std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::cout << std::endl;

        void* exec_mem = VirtualAlloc(nullptr, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!exec_mem) {
            return 1;
        }

        std::copy(shellcode.begin(), shellcode.end(), static_cast<std::uint8_t*>(exec_mem));

        std::cout << "running shell..." << std::endl;
        try {
            using shellcode_test = void(*)();
            auto func = reinterpret_cast<shellcode_test>(exec_mem);
            func();
        }
        catch (...) {
            std::cerr << "error" << std::endl;
        }

        if (exec_mem) {
            VirtualFree(exec_mem, 0, MEM_RELEASE);
        }
    }

    return 1337;
}