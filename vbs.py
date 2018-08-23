#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import re
import struct
import optparse
import pykd

__author__ = 'Binjo'
__version__ = '0.1'
__date__ = '2018-08-21 09:45:37'

"""
vbs.py

python windbg plugin
based on https://github.com/KasperskyLab/VBscriptInternals/

1. trace VBS code, set breakpoint
2. ???
"""

poi = pykd.ptrDWord


class instr:
    def __init__(self, argsize, name, argfmt):
        self.argsize = argsize
        self.name = name
        self.argfmt = argfmt


def get_int8(pos):
    return struct.unpack("b", struct.pack("B", pykd.ptrByte(pos)))[0]


def get_uint8(pos):
    return pykd.ptrByte(pos)


def get_int16(pos):
    return struct.unpack("h", struct.pack("H", pykd.ptrWord(pos)))[0]


def get_uint16(pos):
    return pykd.ptrWord(pos)


def get_int32(pos):
    return struct.unpack("i", struct.pack("I", pykd.ptrDWord(pos)))[0]


def get_uint32(pos):
    return pykd.ptrDWord(pos)


def get_uint64(pos):
    return pykd.ptrQWord(pos)


def get_type0(addr, pos):
    arg0 = get_uint8(pos)
    return " %d" % arg0


def get_type1(addr, pos):
    arg0 = get_uint16(pos)
    return " %d" % arg0


def get_type2(addr, pos):
    arg0 = get_int8(pos)
    return " %d" % arg0


def get_type3(addr, pos):
    arg0 = get_uint32(pos)
    return " %ld" % arg0


def get_type4(addr, pos):
    arg0 = get_int16(pos)
    return " %d" % arg0


def get_type5(addr, pos):
    arg0 = get_uint16(pos)
    return " %d" % arg0


def get_type6(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    return " '%s'" % arg0


def get_type7(addr, pos):
    arg0 = get_uint32(pos)
    return " %04X" % arg0


def get_type8(addr, pos):
    arg0 = get_uint64(pos)
    return " %.17g" % arg0


def get_type9(addr, pos):
    arg0 = get_int16(pos)
    arg1 = get_uint16(pos + 2)
    return " %d %d" % (arg0, arg1)


def get_type10(addr, pos):
    arg0 = get_int16(pos)
    arg1 = get_int16(pos + 2)
    return " %d %d" % (arg0, arg1)


def get_type11(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    arg1 = get_uint8(pos + 4)
    if (arg1 == 0):
        return " '%s' FALSE" % arg0
    else:
        return " '%s' TRUE" % arg0


def get_type12(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    arg1 = get_uint16(pos + 4)
    return " '%s' %d" % (arg0, arg1)


def get_type13(addr, pos):
    arg0 = get_int16(pos)
    arg1 = get_int16(pos + 2)
    arg2 = get_int16(pos + 4)
    return " %d %d %d" % (arg0, arg1, arg2)


def get_type14(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    arg1 = get_int16(pos + 4)
    arg2 = get_int16(pos + 6)
    return " '%s' %d %d" % (arg0, arg1, arg2)


def get_type15(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    arg1 = get_uint32(pos + 4)
    arg2 = get_uint8(pos + 8)
    if (arg2 == 0):
        return " '%s' %u FALSE" % (arg0, arg1)
    else:
        return " '%s' %u TRUE" % (arg0, arg1)


def get_type16(addr, pos):
    arg0 = pykd.loadWStr(addr + get_uint32(pos))
    arg1 = get_int16(pos + 4)
    arg2 = get_uint8(pos + 6)
    if (arg2 == 0):
        return " '%s' %d FALSE" % (arg0, arg1)
    else:
        return " '%s' %d TRUE" % (arg0, arg1)


# Total = 0x6F
vbs_itable = {
    0x00: instr(0, "OP_None", None),
    0x01: instr(0, "OP_FuncEnd", None),
    0x02: instr(0, "OP_Bos0", None),
    0x03: instr(1, "OP_Bos1", get_type0),
    0x04: instr(2, "OP_Bos2", get_type1),
    0x05: instr(4, "OP_Bos4", get_type3),
    0x06: instr(4, "OP_DebugBreak", get_type3),
    0x07: instr(4, "OP_ArrLclDim", get_type9),
    0x08: instr(4, "OP_ArrLclReDim", get_type9),
    0x09: instr(6, "OP_ArrNamDim", get_type12),
    0x0A: instr(6, "OP_ArrNamReDim", get_type12),
    0x0B: instr(1, "OP_IntConst", get_type2),
    0x0C: instr(4, "OP_LngConst", get_type3),
    0x0D: instr(8, "OP_FltConst", get_type8),
    0x0E: instr(4, "OP_StrConst", get_type6),
    0x0F: instr(8, "OP_DateConst", get_type8),
    0x10: instr(0, "OP_False", None),
    0x11: instr(0, "OP_True", None),
    0x12: instr(0, "OP_Null", None),
    0x13: instr(0, "OP_Empty", None),
    0x14: instr(0, "OP_NoArg", None),
    0x15: instr(0, "OP_Nothing", None),
    0x16: instr(5, "OP_ConstSt", get_type11),
    0x17: instr(0, "OP_UNK_17", None),
    0x18: instr(2, "OP_LocalLd", get_type4),
    0x19: instr(2, "OP_LocalAdr", get_type4),
    0x1A: instr(2, "OP_LocalSt", get_type4),
    0x1B: instr(2, "OP_LocalSet", get_type4),
    0x1C: instr(4, "OP_NamedLd", get_type6),
    0x1D: instr(4, "OP_NamedAdr", get_type6),
    0x1E: instr(4, "OP_NamedSt", get_type6),
    0x1F: instr(4, "OP_NamedSet", get_type6),
    0x20: instr(0, "OP_ThisLd", None),
    0x21: instr(0, "OP_ThisSt", None),
    0x22: instr(0, "OP_ThisSet", None),
    0x23: instr(4, "OP_MemLd", get_type6),
    0x24: instr(4, "OP_MemSt", get_type6),
    0x25: instr(4, "OP_MemSet", get_type6),
    0x26: instr(6, "OP_CallNmdLd", get_type12),
    0x27: instr(6, "OP_CallNmdVoid", get_type12),
    0x28: instr(6, "OP_CallNmdAdr", get_type12),
    0x29: instr(6, "OP_CallNmdSt", get_type12),
    0x2A: instr(6, "OP_CallNmdSet", get_type12),
    0x2B: instr(4, "OP_CallLclLd", get_type9),
    0x2C: instr(4, "OP_CallLclVoid", get_type9),
    0x2D: instr(4, "OP_CallLclAdr", get_type9),
    0x2E: instr(4, "OP_CallLclSt", get_type9),
    0x2F: instr(4, "OP_CallLclSet", get_type9),
    0x30: instr(6, "OP_CallMemLd", get_type12),
    0x31: instr(6, "OP_CallMemVoid", get_type12),
    0x32: instr(6, "OP_CallMemSt", get_type12),
    0x33: instr(6, "OP_CallMemSet", get_type12),
    0x34: instr(2, "OP_CallIndLd", get_type5),
    0x35: instr(2, "OP_CallIndVoid", get_type5),
    0x36: instr(2, "OP_CallIndAdr", get_type5),
    0x37: instr(2, "OP_CallIndSt", get_type5),
    0x38: instr(2, "OP_CallIndSet", get_type5),
    0x39: instr(0, "OP_Asg", None),
    0x3A: instr(4, "OP_Jmp", get_type7),
    0x3B: instr(4, "OP_JccTrue", get_type7),
    0x3C: instr(4, "OP_JccFalse", get_type7),
    0x3D: instr(0, "OP_Neg", None),
    0x3E: instr(0, "OP_BitOr", None),
    0x3F: instr(0, "OP_BitXor", None),
    0x40: instr(0, "OP_BitAnd", None),
    0x41: instr(0, "OP_BitNot", None),
    0x42: instr(0, "OP_EQ", None),
    0x43: instr(0, "OP_NE", None),
    0x44: instr(0, "OP_LT", None),
    0x45: instr(0, "OP_LE", None),
    0x46: instr(0, "OP_GT", None),
    0x47: instr(0, "OP_GE", None),
    0x48: instr(0, "OP_Add", None),
    0x49: instr(0, "OP_Sub", None),
    0x4A: instr(0, "OP_Mul", None),
    0x4B: instr(0, "OP_Div", None),
    0x4C: instr(0, "OP_Mod", None),
    0x4D: instr(0, "OP_Eqv", None),
    0x4E: instr(0, "OP_Pow", None),
    0x4F: instr(0, "OP_Imp", None),
    0x50: instr(0, "OP_Is", None),
    0x51: instr(0, "OP_Like", None),
    0x52: instr(0, "OP_Conc", None),
    0x53: instr(0, "OP_Idiv", None),
    0x54: instr(0, "OP_FixType", None),
    0x55: instr(9, "OP_FnBind", get_type15),
    0x56: instr(7, "OP_VarBind", get_type16),
    0x57: instr(0, "OP_FnReturn", None),
    0x58: instr(0, "OP_FnReturnEx", None),
    0x59: instr(0, "OP_Pop", None),
    0x5A: instr(4, "OP_InitClass", get_type6),
    0x5B: instr(4, "OP_CreateClass", get_type6),
    0x5C: instr(9, "OP_FnBindEx", get_type15),
    0x5D: instr(5, "OP_CreateVar", get_type11),
    0x5E: instr(6, "OP_CreateArr", get_type12),
    0x5F: instr(0, "OP_WithPush", None),
    0x60: instr(0, "OP_WithPop", None),
    0x61: instr(0, "OP_WithPop2", None),
    0x62: instr(6, "OP_ForInitLocal", get_type13),
    0x63: instr(6, "OP_ForNextLocal", get_type13),
    0x64: instr(8, "OP_ForInitNamed", get_type14),
    0x65: instr(8, "OP_ForNextNamed", get_type14),
    0x66: instr(1, "OP_OnError", get_type2),
    0x67: instr(4, "OP_CaseEQ", get_type7),
    0x68: instr(4, "OP_CaseNE", get_type7),
    0x69: instr(6, "OP_ForInBegLcl", get_type13),
    0x6A: instr(6, "OP_ForInNxtLcl", get_type13),
    0x6B: instr(8, "OP_ForInBegNmd", get_type14),
    0x6C: instr(8, "OP_ForInNxtNmd", get_type14),
    0x6D: instr(4, "OP_ForInPop", get_type10),
    0x6E: instr(0, "OP_UNK_6E", None),
    0x6F: instr(0, "OP_UNK_6F", None),
}


def pprint(indent_level, text):
    pykd.dprintln("    " * indent_level + text)


def print_list(indent_level, addr, kind, count, list_ptr, start_id):

    pprint(indent_level, "%s count = %d" % (kind, count))

    if (list_ptr):

        indent_level += 1

        for i in range(count):

            name_pos = get_uint32(list_ptr + 8 * i)
            flags = get_uint32(list_ptr + 8 * i + 4)

            if (start_id):
                string = "%s %3d =" % (kind, start_id * (i + 1))
            else:
                string = "%s =" % kind

            if (start_id >= 0):

                if (start_id):
                    string += "    "

                elif (flags & 2):
                    string += " pri"

                else:
                    string += " pub"

            elif (flags & 0x200):
                string += " ref"

            else:
                string += " val"

            if (flags & 0x100):
                string += " Variant ()"
            else:
                string += " Variant   "

            string += " '%s'" % pykd.loadWStr(addr + name_pos)

            pprint(indent_level, string)


class Vbs:

    def __init__(self, runtime, maxvisit=10):
        self._scriptrt = runtime
        self._maxvisit = maxvisit
        self._visitcnt = dict()
        self._scriptemt = poi(runtime + 0xC0)
        self._pfuncs = self._scriptemt + poi(self._scriptemt + 0x10)
        self._fncnt = poi(self._scriptemt + 0x14)
        self._pbos_info = self._scriptemt + poi(self._scriptemt + 0x1C)
        self._pbos_data = self._scriptemt + poi(self._scriptemt + 0x28)
        self._boscode = ""
        self._funcs = list()

        for i in xrange(self._fncnt):
            pfn = self._scriptemt + poi(self._pfuncs + i * 4)
            code_start = self._scriptemt + poi(pfn + 8)
            code_len = poi(pfn + 0xC)
            self._funcs.append(dict([
                ('pfn', pfn),
                ('code_start', code_start),
                ('code_len', code_len),
                ('bos_info', self._pbos_info + poi(pfn + 0x10) * 8),
                ('pcodes', pykd.loadBytes(code_start, code_len)),
            ]))

    @property
    def pfns(self):
        """list of pfn
        """
        return [k['pfn'] for k in self._funcs]

    @property
    def codes(self):
        """list of code_start
        """
        return [k['code_start'] for k in self._funcs]

    def maxvisit_p(self, pc):
        """
        """
        if pc not in self._visitcnt.keys():
            self._visitcnt[pc] = 0
        else:
            self._visitcnt[pc] += 1
        return (self._visitcnt[pc] >= self._maxvisit)

    def pc2pfn(self, pc):
        """get pfn dict from pc
        """
        return self.pfns[self.codes.index(pc)]

    def pfn2pc(self, pfn):
        """
        """
        return self.codes[self.pfns.index(pfn)]

    def dump_func(self, pfnc):
        """return boscode(original code statement)
        """
        pykd.dprintln("[+] vmpc = %08X" % self.pfn2pc(pfnc))
        self._boscode = ""      # reset bos code
        self.dump_meta(pfnc)
        self.dump_code(pfnc)
        return self._boscode

    def dump_meta(self, pfnc):
        """
        """
        if pfnc not in self.pfns:
            return

        addr = self._scriptemt
        func_id = self.pfns.index(pfnc)

        name_pos = poi(pfnc)
        stack = poi(pfnc + 4)

        if (func_id):
            if (name_pos):
                name = pykd.loadWStr(addr + name_pos)
                pykd.dprintln("Function %d ('%s') [max stack = %u]:" % (func_id, name, stack))
            else:
                pykd.dprintln("Function %d [max stack = %u]:" % (func_id, stack))
        else:
                pykd.dprintln("Global code [max stack = %u]:" % stack)

        flags = poi(pfnc + 44)

        if (flags):

            string = "flags     = (%04lX)" % flags

            if (flags & 0x8000):
                string += " noconnect"

            if (flags & 0x4000):
                string += " sub"

            if (flags & 0x2000):
                string += " explicit"

            if (flags & 2):
                string += " private"

            pykd.dprintln(string)

        arg_count = get_int16(pfnc + 36)
        arg_addr = pfnc + 48

        if (func_id or arg_count > 0):
            print_list(1, addr, "arg", arg_count, arg_addr, -1)

        lcl_count = get_int16(pfnc + 38)
        lcl_addr = arg_addr + 8 * arg_count

        if (func_id or lcl_count > 0):
            print_list(1, addr, "lcl", lcl_count, lcl_addr, 1)

        tmp_count = get_int16(pfnc + 40)

        if (tmp_count > 0):
            print_list(1, addr, "tmp", tmp_count, 0, 1)

    def dump_code(self, pfnc):
        """
        """
        if pfnc not in self.pfns:
            return

        addr = self._scriptemt

        code_start = addr + poi(pfnc + 8)
        code_end = code_start + poi(pfnc + 0xC)

        bos_info = self._pbos_info + poi(pfnc + 0x10) * 8

        pprint(0, "Pcode:")

        position = code_start

        while (position < code_end):

            opcode = get_uint8(position)

            if (opcode >= 0x6F):
                string = "ERROR(%u)" % opcode
                pprint(1, string)
                break

            if opcode in (3, 4, 5):

                if (opcode == 3):
                    value = get_uint8(position + 1)

                elif (opcode == 4):
                    value = get_uint16(position + 1)

                elif (opcode == 5):
                    value = get_uint32(position + 1)

                bos_info_pos = bos_info + 8 * value

                bos_start = get_uint32(bos_info_pos)
                bos_length = get_uint32(bos_info_pos + 4)

                string = "***BOS(%ld,%ld)***" % (bos_start, bos_start + bos_length)

                if (self._pbos_data):
                    boscode = pykd.loadWChars(self._pbos_data + 2 * bos_start, bos_length)
                    string += " %s *****" % boscode
                    self._boscode += boscode

                pprint(1, string)

            string = "%08X - %04X    " % (position, position - code_start)

            ops = "%02X " % opcode
            ops += " ".join([
                "%02X" % get_uint8(i) for i in xrange(position + 1, position + 1 + vbs_itable[opcode].argsize)])

            string += "%-30s %-16s" % (ops, vbs_itable[opcode].name)

            if (vbs_itable[opcode].argfmt is not None):
                string += vbs_itable[opcode].argfmt(addr, position + 1)

            pprint(1, string)

            position += 1 + vbs_itable[opcode].argsize


class VbsEventHandler(pykd.eventHandler):

    def __init__(self, opts):
        super(VbsEventHandler, self).__init__()
        self._mbase = 0
        self._ssize = 0
        self._vbs = {}
        self._vm = None
        self._opts = opts
        self._breaks = []

    def bp(self, addr, handler=None, breakin=False):
        """wrapper of setBp
        """
        handler_ = handler or self.handleVbsBP
        if addr in self._vbs:
            self._vbs[addr].update(
                {'bpe': breakin or False,
                 'bp': pykd.setBp(addr, handler_)})
        else:
            self._vbs[addr] = {'bpe': breakin or False,
                               'bp': pykd.setBp(addr, handler_)}

    def be(self, addr, enable=True):
        """enable or disable bp
        """
        if addr in self._vbs and 'bpe' in self._vbs[addr]:
            self._vbs[addr]['bpe'] = enable or False

    def bc(self, addr):
        """remove breakpoint on address
        """
        if addr in self._vbs and 'bp' in self._vbs[addr]:
            self._vbs[addr]['bp'].remove()
            self._vbs[addr]['bpe'] = False

    def break_p(self, addr):
        """check if should break in
        """
        return addr in self._vbs and \
            'bpe' in self._vbs[addr] and \
            self._vbs[addr]['bpe']

    def onLoadModule(self, mbase, mname):
        # pykd.dprintln( "onLoadModule.... %s, %s" % (hex(mbase), mname) )
        if 'vbscript' in mname:
            self._mbase = mbase
            # .text section size
            self._ssize = poi(mbase + poi(mbase + 0x3c) + 0x100)

            pykd.dprintln(
                '[!] vbscript module base: %08x, section size: %08x' %
                (self._mbase, self._ssize))

            if self._opts.breaks:
                for b in self._opts.breaks.split(','):  # FIXME code statement
                    if re.match(r'^[0-9a-fA-F]+$', b.strip()):
                        # offset, just set bp
                        pykd.dprintln(
                            '[!] setting break point @ %08x' %
                            (int(b, 16) + self._mbase))
                        self.bp(int(b, 16) + self._mbase, breakin=True)
                    else:
                        self._breaks.append(b)

            if not self.hookRunNoEH():
                return pykd.executionStatus.Break

        return pykd.eventResult.Proceed

    def hookRunNoEH(self):
        """
        """
        runnoeh = pykd.searchMemory(
            self._mbase, 0xfff000,
            [chr(c) for c in [
                0x8B, 0x83, 0xB4, 0x00, 0x00, 0x00,  # mov eax, [ebx+0B4h]
                0x0F, 0xB6, 0x08,                    # movzx ecx, byte ptr [eax]
                0x8D, 0x70, 0x01,                    # lea esi, [eax+1]
                0x89, 0xB3, 0xB4, 0x00, 0x00, 0x00,  # mov [ebx+0B4h], esi
                0x83, 0xF9, 0x6F,                    # cmp ecx, 6Fh
            ]]
        )
        if not runnoeh:
            pykd.dprintln("[-] oooops, failed to find CScriptRuntime::RunNoEH")
            return False

        pykd.dprintln("[+] Found CScriptRuntime::RunNoEH routine @ %08x" % runnoeh)
        self.bp(runnoeh, breakin=True)

        return True

    def handleVbsBP(self):
        """
        """
        if not self._vm:
            self._vm = Vbs(pykd.reg("ebx"))

        vmpc = poi(pykd.reg("ebx") + 0xB4)
        if (vmpc in self._vm.codes and not self._vm.maxvisit_p(vmpc)):
            boscode = self._vm.dump_func(self._vm.pc2pfn(vmpc))
            if self._opts.breaks:
                for b in self._opts.breaks.split(','):
                    if b.lower() in boscode.lower():
                        return pykd.eventResult.Break
            if not self._opts.trace:
                return pykd.eventResult.Break

        return pykd.eventResult.Proceed


def main():
    """TODO
    """
    opt = optparse.OptionParser(
        usage='usage: %prog [options]\n', version='%prog ' + __version__)
    opt.add_option('-b', '--breaks', help='list of function names to break in')
    opt.add_option('-t', '--trace', help='just trace, do not break', default=False, action="store_true")
    (opts, args) = opt.parse_args()

    vbs = VbsEventHandler(opts)
    if not os.path.isdir('c:\\_virus'):
        os.mkdir('c:\\_virus')
    pykd.dbgCommand(".logopen /t c:\\_virus\\vbs.txt")
    pykd.dbgCommand(".childdbg 1")
    pykd.dprintln("hello vbs")
    pykd.go()


# -------------------------------------------------------------------------
if __name__ == '__main__':
    main()
# -------------------------------------------------------------------------
# EOF
