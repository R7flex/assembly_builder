# ShellcodeCrafter

A modern C++20-based x64 assembly code generator for creating shellcode.

## Overview

ShellcodeCrafter is a powerful and type-safe C++20 library designed to generate x64 assembly code programmatically. It provides a high-level interface for creating shellcode while maintaining type safety and modern C++ practices.

## Features

- 🚀 Modern C++20 implementation
- 🔒 Type-safe assembly instruction generation
- 💻 x64 architecture support
- 📦 Header-only library
- 🛠️ Easy-to-use builder pattern
- 🔄 Support for common x64 instructions (MOV, CALL, RET, etc.)
- 🧩 Extensible architecture for adding new instructions

## Requirements

- C++20 compatible compiler
- x64 architecture

## Quick Start

```cpp
#include <iostream>
#include <iomanip>
#include <windows.h>

#include "assembly_builder.hpp"
using namespace shellcode;

void example_function() {
    std::cout << "huso niye facebook oldun" << std::endl;
}

int main() {
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
```

## Supported Instructions

- MOV
- CALL
- RET
- PUSH
- POP
- ADD
- SUB
- MUL
- DIV
- AND
- OR
- XOR
- NOT
- NEG
- JMP
- JE
- JNE
- JG
- JGE
- JL
- JLE
- CMP
- TEST
- LEA
- NOP

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- Modern C++ features for type safety
- x64 architecture documentation
- C++20 standard library

## Author
R7flex

## Support
If you find this project useful, please consider giving it a ⭐️ on GitHub!
