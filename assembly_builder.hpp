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
            MOV, PUSH, POP, CALL, RET,
        };

        enum class x64_register {
            RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI,
            R8, R9, R10, R11, R12, R13, R14, R15
        };

        struct mem_indirect {
            x64_register base;
        };

        using operand = std::variant<x64_register, std::uint64_t, void*, mem_indirect>;

        x64_type type;
        std::vector<operand> operands;

        assembly_instruction(x64_type t, std::initializer_list<operand> ops = {}) : type(t), operands(ops) {}
    };

    class assemby_builder {
        std::vector<assembly_instruction> instructions;
        std::vector<std::uint8_t> shellcode;

        static constexpr std::uint8_t get_register_id(assembly_instruction::x64_register reg) {
            return static_cast<std::uint8_t>(reg);
        }

        static constexpr bool is_extended(assembly_instruction::x64_register reg) {
            return get_register_id(reg) >= 8;
        }

        //simple emit
        void emit_rex(bool w, bool r, bool x, bool b) {
            std::uint8_t rex = 0x40;
            if (w) rex |= 0x08;
            if (r) rex |= 0x04;
            if (x) rex |= 0x02;
            if (b) rex |= 0x01;
            shellcode.push_back(rex);
        }

        //https://i.sstatic.net/II1Zl.png
        void generate_modrm(std::uint8_t mod, std::uint8_t reg, std::uint8_t rm) {
            shellcode.push_back(static_cast<std::uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
        }

        void generate_mov(const assembly_instruction& inst) {
            if (inst.operands.size() != 2) return;

            const auto& dest = inst.operands[0];
            const auto& src = inst.operands[1];

            // MOV reg, imm64 --> 1 https://stackoverflow.com/questions/48288644/how-does-rip-relative-addressing-perform-compared-to-mov-reg-imm64
            if (std::holds_alternative<assembly_instruction::x64_register>(dest) && (std::holds_alternative<std::uint64_t>(src) || std::holds_alternative<void*>(src))) {
                auto dest_reg = std::get<assembly_instruction::x64_register>(dest);
                std::uint64_t imm = std::holds_alternative<std::uint64_t>(src) ? std::get<std::uint64_t>(src) : reinterpret_cast<std::uint64_t>(std::get<void*>(src));

                emit_rex(true, false, false, is_extended(dest_reg));
                shellcode.push_back(0xB8 + (get_register_id(dest_reg) & 0x7));
                auto* imm_ptr = reinterpret_cast<const std::uint8_t*>(&imm);
                shellcode.insert(shellcode.end(), imm_ptr, imm_ptr + sizeof(imm));
                return;
            }
            
            // MOV reg, reg --> 2
            if (std::holds_alternative<assembly_instruction::x64_register>(dest) && std::holds_alternative<assembly_instruction::x64_register>(src)) {
                auto dest_reg = std::get<assembly_instruction::x64_register>(dest);
                auto src_reg = std::get<assembly_instruction::x64_register>(src);

                emit_rex(true, is_extended(src_reg), false, is_extended(dest_reg));
                shellcode.push_back(0x89); // MOV r/m64, r64
                generate_modrm(0b11, get_register_id(src_reg), get_register_id(dest_reg));
                return;
            }

            //https://stackoverflow.com/questions/35806498/the-difference-between-mov-reg-reg-mov-reg-reg

            // MOV reg, [reg] --> 3
            if (std::holds_alternative<assembly_instruction::x64_register>(dest) && std::holds_alternative<assembly_instruction::mem_indirect>(src)) {
                auto dest_reg = std::get<assembly_instruction::x64_register>(dest);
                auto base = std::get<assembly_instruction::mem_indirect>(src).base;

                emit_rex(true, is_extended(dest_reg), false, is_extended(base));
                shellcode.push_back(0x8B); // MOV r64, r/m64
                generate_modrm(0b00, get_register_id(dest_reg), get_register_id(base));
                return;
            }

            // MOV [reg], reg --> 4
            if (std::holds_alternative<assembly_instruction::mem_indirect>(dest) && std::holds_alternative<assembly_instruction::x64_register>(src)) {
                auto base = std::get<assembly_instruction::mem_indirect>(dest).base;
                auto src_reg = std::get<assembly_instruction::x64_register>(src);

                emit_rex(true, is_extended(src_reg), false, is_extended(base));
                shellcode.push_back(0x89); // MOV r/m64, r64
                generate_modrm(0b00, get_register_id(src_reg), get_register_id(base));
                return;
            }
        }

        void generate_call(const assembly_instruction& inst) {
            if (inst.operands.size() != 1) return;

            const auto& target = inst.operands[0];

            //modrm veya relative
            if (std::holds_alternative<assembly_instruction::x64_register>(target)) {
                auto reg = std::get<assembly_instruction::x64_register>(target);
                emit_rex(false, false, false, is_extended(reg));
                shellcode.push_back(0xFF);
                generate_modrm(0b11, 2, get_register_id(reg));
            }
            else if (std::holds_alternative<void*>(target)) {
                std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(std::get<void*>(target));
                shellcode.push_back(0xE8); // --> relative
                std::int32_t rel = static_cast<std::int32_t>(addr - (reinterpret_cast<std::uintptr_t>(shellcode.data()) + shellcode.size() + 5));
                auto* ptr = reinterpret_cast<const std::uint8_t*>(&rel);
                shellcode.insert(shellcode.end(), ptr, ptr + 4);
            }
        }

        void generate_push(const assembly_instruction& inst) {
            if (inst.operands.size() != 1) return;
            const auto& op = inst.operands[0];

            //extend control
            if (std::holds_alternative<assembly_instruction::x64_register>(op)) {
                auto reg = std::get<assembly_instruction::x64_register>(op);
                if (is_extended(reg)) {
                    emit_rex(false, false, false, true); //
                }
                shellcode.push_back(0x50 + (get_register_id(reg) & 0x7));
            }
        }

        void generate_pop(const assembly_instruction& inst) {
            if (inst.operands.size() != 1) return;
            const auto& op = inst.operands[0];

            if (std::holds_alternative<assembly_instruction::x64_register>(op)) {
                auto reg = std::get<assembly_instruction::x64_register>(op);
                if (is_extended(reg)) {
                    emit_rex(false, false, false, true);
                }
                shellcode.push_back(0x58 + (get_register_id(reg) & 0x7));
            }
        }

        void generate_ret(const assembly_instruction&) {
            shellcode.push_back(0xC3);
        }

    public:
        assemby_builder& add(assembly_instruction::x64_type type, std::initializer_list<assembly_instruction::operand> operands = {}) {
            instructions.emplace_back(type, operands);
            return *this;
        }

        //added push ve pop
        std::vector<std::uint8_t> build() {
            shellcode.clear();
            for (const auto& inst : instructions) {
                switch (inst.type) {
                case assembly_instruction::x64_type::MOV:  generate_mov(inst); break;
                case assembly_instruction::x64_type::CALL: generate_call(inst); break;
                case assembly_instruction::x64_type::PUSH: generate_push(inst); break;
                case assembly_instruction::x64_type::POP:  generate_pop(inst); break;
                case assembly_instruction::x64_type::RET:  generate_ret(inst); break;
                default: break;
                }
            }
            return shellcode;
        }
    };
}
