#pragma once
#include <array>
#include <cstdint>
#include <string_view>
#include <vector>
#include <initializer_list>
#include <variant>
#include <memory>

namespace shellcode {
    struct assembly_instruction {
        enum class x64_type {
            MOV, PUSH, POP, ADD, SUB, MUL, DIV,
            AND, OR, XOR, NOT, NEG,
            CALL, RET, JMP, JE, JNE, JG, JGE, JL, JLE,
            CMP, TEST, LEA,
            NOP
        };

        enum class x64_register {
            RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP,
            R8, R9, R10, R11, R12, R13, R14, R15
        };

        using operand = std::variant<x64_register, std::uint64_t, void*>;

        x64_type type;
        std::vector<operand> operands;

        assembly_instruction(x64_type t, std::initializer_list<operand> ops = {}): type(t), operands(ops) {}
    };

    class assemby_builder {
        std::vector<assembly_instruction> instructions;
        std::vector<std::uint8_t> shellcode;

        static constexpr auto get_register_code(assembly_instruction::x64_register reg)->std::array<std::uint8_t, 1> {
            constexpr std::array<std::uint8_t, 16> reg_codes = {
                0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57
            };
            return { reg_codes[static_cast<std::size_t>(reg)] };
        }

        void generate_mov(const assembly_instruction& inst) {
            if (inst.operands.size() != 2) return;

            const auto& dest = inst.operands[0];
            const auto& src = inst.operands[1];

            if (std::holds_alternative<assembly_instruction::x64_register>(dest)) {
                auto dest_reg = std::get<assembly_instruction::x64_register>(dest);

                if (std::holds_alternative<assembly_instruction::x64_register>(src)) {
                    auto src_reg = std::get<assembly_instruction::x64_register>(src);
                    auto code = std::array{ 0x48, 0x89 };
                    shellcode.insert(shellcode.end(), code.begin(), code.end());
                    shellcode.push_back(get_register_code(src_reg)[0]);
                    shellcode.push_back(get_register_code(dest_reg)[0]);
                }
                else if (std::holds_alternative<std::uint64_t>(src) || std::holds_alternative<void*>(src)) {
                    std::uint64_t imm = std::holds_alternative<std::uint64_t>(src) ? std::get<std::uint64_t>(src) : reinterpret_cast<std::uint64_t>(std::get<void*>(src));
                    shellcode.push_back(0x48);
                    shellcode.push_back(0xB8 + static_cast<std::uint8_t>(dest_reg));
                    auto* imm_ptr = reinterpret_cast<const std::uint8_t*>(&imm);
                    shellcode.insert(shellcode.end(), imm_ptr, imm_ptr + sizeof(imm));
                }
            }
        }

        void generate_call(const assembly_instruction& inst) {
            if (inst.operands.size() != 1) return;

            if (std::holds_alternative<assembly_instruction::x64_register>(inst.operands[0])) {
                auto reg = std::get<assembly_instruction::x64_register>(inst.operands[0]);
                shellcode.push_back(0xFF);
                shellcode.push_back(0xD0 + static_cast<std::uint8_t>(reg));
            }
        }

        void generate_ret(const assembly_instruction& inst) {
            shellcode.push_back(0xC3);
        }

    public:
        assemby_builder& add(assembly_instruction::x64_type type, std::initializer_list<assembly_instruction::operand> operands = {}) {
            instructions.emplace_back(type, operands);
            return *this;
        }

        std::vector<std::uint8_t> build() {
            shellcode.clear();

            for (const auto& inst : instructions) {
                switch (inst.type) {
                case assembly_instruction::x64_type::MOV:
                    generate_mov(inst);
                    break;
                case assembly_instruction::x64_type::CALL:
                    generate_call(inst);
                    break;
                case assembly_instruction::x64_type::RET:
                    generate_ret(inst);
                    break;
                default:
                    break;
                }
            }

            return shellcode;
        }
    };
}