import ida_ua

# Jump instructions
JMPS = (
    idaapi.NN_jmp,      # Jump
    idaapi.NN_jmpfi,    # Indirect Far Jump
    idaapi.NN_jmpni,    # Indirect Near Jump
    idaapi.NN_jmpshort  # Jump Short (not used)
)

# Conditional jump instructions
CJMPS = (
    idaapi.NN_ja,       # Jump if Above (CF=0 & ZF=0)
    idaapi.NN_jae,      # Jump if Above or Equal (CF=0)
    idaapi.NN_jb,       # Jump if Below (CF=1)
    idaapi.NN_jbe,      # Jump if Below or Equal (CF=1 | ZF=1)
    idaapi.NN_jc,       # Jump if Carry (CF=1)
    idaapi.NN_jcxz,     # Jump if CX is 0
    idaapi.NN_jecxz,    # Jump if ECX is 0
    idaapi.NN_jrcxz,    # Jump if RCX is 0
    idaapi.NN_je,       # Jump if Equal (ZF=1)
    idaapi.NN_jg,       # Jump if Greater (ZF=0 & SF=OF)
    idaapi.NN_jge,      # Jump if Greater or Equal (SF=OF)
    idaapi.NN_jl,       # Jump if Less (SF!=OF)
    idaapi.NN_jle,      # Jump if Less or Equal (ZF=1 | SF!=OF)
    idaapi.NN_jna,      # Jump if Not Above (CF=1 | ZF=1)
    idaapi.NN_jnae,     # Jump if Not Above or Equal (CF=1)
    idaapi.NN_jnb,      # Jump if Not Below (CF=0)
    idaapi.NN_jnbe,     # Jump if Not Below or Equal (CF=0 & ZF=0)
    idaapi.NN_jnc,      # Jump if Not Carry (CF=0)
    idaapi.NN_jne,      # Jump if Not Equal (ZF=0)
    idaapi.NN_jng,      # Jump if Not Greater (ZF=1 | SF!=OF)
    idaapi.NN_jnge,     # Jump if Not Greater or Equal (ZF=1)
    idaapi.NN_jnl,      # Jump if Not Less (SF=OF)
    idaapi.NN_jnle,     # Jump if Not Less or Equal (ZF=0 & SF=OF)
    idaapi.NN_jno,      # Jump if Not Overflow (OF=0)
    idaapi.NN_jnp,      # Jump if Not Parity (PF=0)
    idaapi.NN_jns,      # Jump if Not Sign (SF=0)
    idaapi.NN_jnz,      # Jump if Not Zero (ZF=0)
    idaapi.NN_jo,       # Jump if Overflow (OF=1)
    idaapi.NN_jp,       # Jump if Parity (PF=1)
    idaapi.NN_jpe,      # Jump if Parity Even (PF=1)
    idaapi.NN_jpo,      # Jump if Parity Odd  (PF=0)
    idaapi.NN_js,       # Jump if Sign (SF=1)
    idaapi.NN_jz,       # Jump if Zero (ZF=1)
    idaapi.NN_loopw,    # Loop while ECX != 0
    idaapi.NN_loop,     # Loop while CX != 0
    idaapi.NN_loopd,    # Loop while ECX != 0
    idaapi.NN_loopq,    # Loop while RCX != 0
    idaapi.NN_loopwe,   # Loop while CX != 0 and ZF=1
    idaapi.NN_loope,    # Loop while rCX != 0 and ZF=1
    idaapi.NN_loopde,   # Loop while ECX != 0 and ZF=1
    idaapi.NN_loopqe,   # Loop while RCX != 0 and ZF=1
    idaapi.NN_loopwne,  # Loop while CX != 0 and ZF=0
    idaapi.NN_loopne,   # Loop while rCX != 0 and ZF=0
    idaapi.NN_loopdne,  # Loop while ECX != 0 and ZF=0
    idaapi.NN_loopqne   # Loop while RCX != 0 and ZF=0
)

RETS = (
    idaapi.NN_retf,
    idaapi.NN_retfd,
    idaapi.NN_retfq,
    idaapi.NN_retfw,
    idaapi.NN_retn,
    idaapi.NN_retnd,
    idaapi.NN_retnq,
    idaapi.NN_retnw,
    idaapi.NN_iretw, 
    idaapi.NN_iret,
    idaapi.NN_iretd,
    idaapi.NN_iretq
)

MAX_INSN = 1000

f = open('C:\\trace.txt', 'w')

start_ea = ida_kernwin.get_screen_ea() # EA is caller address 
msg = "Start address is 0x%08x" % start_ea
print(msg)
f.write(msg + '\n')
next_start_ea = ida_bytes.next_head(start_ea, ida_idaapi.BADADDR)
seg_start = idc.get_segm_start(start_ea)
seg_end = idc.get_segm_end(seg_start)


insn = ida_ua.insn_t()
ida_dbg.refresh_debugger_memory()

i = 0

while i < MAX_INSN:
        ida_dbg.step_into()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
        mnem = idc.print_insn_mnem(here())
        opnd0 = idc.print_operand(here(), 0)
        msg = "0x%08x %s %s" % (here(), mnem, opnd0)
        print(msg)
        f.write(msg + '\n')
        if mnem == 'add' and opnd0 == 'esp':
            prev_ea = here()
            ida_dbg.step_into()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
            msg = "Check Target 0x%08x %s %s" % (here(), idc.print_insn_mnem(here()), idc.print_operand(here(), 0))
            print(msg)
            f.write(msg + '\n')
            idc.create_insn(here())
            ida_ua.decode_insn(insn, here())
            
            if not(insn.itype in JMPS) and not(insn.itype in CJMPS) and not(insn.itype in RETS):
                target_ea = prev_ea
                msg = "Target address is 0x%08x" % target_ea
                print(msg)
                f.write(msg + '\n')
                offset = target_ea - next_start_ea
                msg = hex(offset)
                print(msg)
                f.write(msg + '\n')
                # Patch to call target function address 
                idc.patch_byte(start_ea + 1, offset & 0x000000FF)
                idc.patch_byte(start_ea + 2, offset >> 8 & 0x000000FF)
                idc.patch_byte(start_ea + 3, offset >> 16 & 0x000000FF)
                idc.patch_byte(start_ea + 4, offset >> 24 & 0x000000FF)

                break
        i = i + 1


if i == MAX_INSN:
    msg = "Target address NOT FOUND!"
    print(msg)
    f.write(msg + '¥n')

f.close()
