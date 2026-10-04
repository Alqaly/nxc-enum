#!/usr/bin/env python3
"""Create a static NetExec protocol/module capability snapshot from source."""
import argparse
import ast
import json
from pathlib import Path


def literal(node):
    try:
        value = ast.literal_eval(node)
        return sorted(value) if isinstance(value, set) else value
    except (ValueError, TypeError):
        return None


def protocols(root):
    result = {}
    for path in sorted((root / "nxc" / "protocols").glob("*/proto_args.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        options = []
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_argument":
                continue
            names = [literal(a) for a in call.args]
            names = [n for n in names if isinstance(n, str) and n.startswith("-")]
            if not names:
                continue
            kwargs = {kw.arg: literal(kw.value) for kw in call.keywords if kw.arg}
            options.append({"flags": names, "help": kwargs.get("help"), "metavar": kwargs.get("metavar"),
                            "choices": kwargs.get("choices"), "nargs": kwargs.get("nargs")})
        result[path.parent.name] = {"source": str(path.relative_to(root)), "options": options}
    return result


def modules(root):
    result = []
    for path in sorted((root / "nxc" / "modules").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        module_class = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "NXCModule"), None)
        if not module_class:
            continue
        values = {}
        callbacks = []
        options_doc = ""
        for node in module_class.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {
                        "name", "description", "supported_protocols", "opsec_safe", "multiple_hosts"
                    }:
                        values[target.id] = literal(node.value)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "options":
                    options_doc = ast.get_docstring(node) or ""
                elif node.name.startswith("on_"):
                    callbacks.append(node.name)
        if values.get("name"):
            result.append({"source": str(path.relative_to(root)), **values,
                           "callbacks": callbacks, "options_documentation": options_doc})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("netexec_source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.netexec_source.resolve()
    commit = "unknown"
    head = root / ".git" / "HEAD"
    if head.is_file():
        ref = head.read_text().strip()
        candidate = root / ".git" / ref.removeprefix("ref: ")
        if candidate.is_file():
            commit = candidate.read_text().strip()
        elif len(ref) == 40:
            commit = ref
    data = {"netexec_commit": commit, "protocols": protocols(root), "modules": modules(root),
            "meaning": "Static source inventory. Runtime capabilities.json and module-inventory.json remain authoritative for the installed NetExec."}
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"{len(data['protocols'])} protocols, {len(data['modules'])} modules")


if __name__ == "__main__":
    main()
