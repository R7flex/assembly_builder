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
#include "shellcode.hpp"

int main() {
    shellcode::assemby_builder builder;
    
    // Create shellcode that calls MessageBoxA
    builder
        .add(shellcode::assembly_instruction::x64_type::MOV, 
             {shellcode::assembly_instruction::x64_register::RAX, 
              reinterpret_cast<void*>(MessageBoxA)})
        .add(shellcode::assembly_instruction::x64_type::CALL, 
             {shellcode::assembly_instruction::x64_register::RAX})
        .add(shellcode::assembly_instruction::x64_type::RET);
    
    auto shellcode = builder.build();
    // Use the generated shellcode...
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
