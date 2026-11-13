"""Symbol-bounded native function/assembly index; no decompilation claims."""
import json
import os
import re
import shutil
from pathlib import Path

from .errors import AnalysisError
from .evidence import private_write
from .native_config import run_tool


def objdump():
    candidate = os.environ.get("NATIVE_SECURITY_OBJDUMP") or shutil.which("llvm-objdump")
    if not candidate:
        candidate = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump"
    path = Path(candidate)
    if not path.is_file():
        raise AnalysisError("llvm_objdump_missing")
    return path


def parse(symbols, assembly):
    names = {}
    for line in symbols.splitlines():
        tokens = line.split()
        if not tokens or not re.fullmatch(r"[0-9a-fA-F]{4,16}", tokens[0]) or "F" not in tokens:
            continue
        start = tokens.index("F") + 2
        if start < len(tokens) and re.fullmatch(r"[0-9a-fA-F]{4,16}", tokens[start]):
            start += 1
        while start < len(tokens) and tokens[start] in {".hidden", ".protected"}:
            start += 1
        if start < len(tokens):
            names[format(int(tokens[0], 16), "x")] = " ".join(tokens[start:])
    functions, edges, current = [], [], None
    indexed, functions_omitted, edges_omitted, indirect = {}, 0, 0, 0
    for line in assembly.splitlines():
        if line.startswith("Disassembly of section"):
            current = None
            continue
        header = re.match(r"^([0-9a-fA-F]+) <(.+)>:$", line)
        if header:
            address = format(int(header[1], 16), "x")
            if address in names:
                if address not in indexed and len(functions) >= 2000:
                    functions_omitted += 1; current = None; continue
                if address not in indexed:
                    current = {"identity": address, "name": names[address], "address": address,
                               "body": "", "body_format": "assembly", "body_truncated": False,
                               "file_offset": None, "origin": "defined_function_symbol"}
                    indexed[address] = current
                    functions.append(current)
                else:
                    current = indexed[address]
            continue
        if current is None:
            continue
        if len(current["body"]) < 12000:
            current["body"] += line[:12000 - len(current["body"])] + "\n"
        elif line.strip():
            current["body_truncated"] = True
        insn = re.match(r"\s*([0-9a-fA-F]+):\s+([a-zA-Z][a-zA-Z0-9.]*)\s*(.*)$", line)
        if not insn:
            continue
        mnemonic, operand = insn[2].lower(), insn[3].strip()
        indirect_mnemonics = {"blr", "br", "blraa", "blrab", "blraaz", "blrabz", "braa", "brab", "braaz", "brabz"}
        if mnemonic not in {"bl", "blx", "call", "callq"} | indirect_mnemonics:
            continue
        target = re.match(r"(?:0x)?([0-9a-fA-F]+)(?:\s|$)", operand)
        computed = mnemonic in indirect_mnemonics or target is None or operand.startswith("*")
        if computed:
            indirect += 1
        if len(edges) >= 12000:
            edges_omitted += 1; continue
        target_address = format(int(target[1], 16), "x") if not computed else None
        edges.append({"from": current["identity"], "to": target_address,
                      "target_name": names.get(target_address), "site": format(int(insn[1], 16), "x"),
                      "kind": "indirect_branch_unresolved" if computed else "static_call_reference"})
    return {"schema": "llvm-index/1", "functions": functions, "strings": [], "edges": edges,
            "coverage": {"symbols_discovered": len(names), "functions_indexed": len(functions),
                         "functions_omitted": functions_omitted, "bodies_recovered": len(functions),
                         "edges_indexed": len(edges), "edges_omitted": edges_omitted,
                         "computed_branches": indirect, "decompilation_performed": False,
                         "string_analysis_performed": False, "relationship_coverage": "partial"},
            "limitations": ["仅索引符号表 F 类型且有反汇编标签的函数；裁剪符号可能没有可恢复节点。",
                            "正文为汇编，不是伪代码或原始源码；未做字符串数据引用分析。",
                            "只记录已识别指令中的直接调用；间接分支、尾调用、ObjC/Swift 派发不完整。",
                            "地址属于选定切片和工具地址空间，未映射原始文件偏移。"]}


def llvm_index(input_file, directory, deadline):
    tool = objdump()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_tool([str(tool), "--version"], directory / "llvm.version", directory / "llvm.version.stderr", deadline, 65536)
    run_tool([str(tool), "--syms", str(input_file)], directory / "llvm.symbols", directory / "llvm.symbols.stderr", deadline, 4 * 1024 * 1024)
    run_tool([str(tool), "--disassemble", "--no-show-raw-insn", "--print-imm-hex", str(input_file)],
             directory / "llvm.assembly", directory / "llvm.assembly.stderr", deadline, 12 * 1024 * 1024)
    result = parse((directory / "llvm.symbols").read_text(errors="replace"), (directory / "llvm.assembly").read_text(errors="replace"))
    result["engine_version"] = (directory / "llvm.version").read_text(errors="replace").splitlines()[0][:256]
    output = directory / "index.json"
    private_write(output, json.dumps(result, ensure_ascii=False).encode())
    return output
