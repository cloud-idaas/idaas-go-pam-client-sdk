"""Check public operation and construction contracts against a read-only checkout."""

import argparse
import ast
import json
from pathlib import Path
import re
import sys

from tree_sitter import Language, Parser
import tree_sitter_java
import tree_sitter_typescript


ROOT = Path(__file__).resolve().parent.parent
LANGUAGES = ("java", "python", "typescript")


def modifiers(node):
    result = set()
    for child in node.children:
        if child.type == "modifiers":
            result.update(child.text.decode().split())
        elif child.type in {"accessibility_modifier", "static", "get", "set"}:
            result.add(child.text.decode())
    return result


def class_members(language, source, class_path):
    """Find a public class by its direct nesting path, without executing code."""
    if language == "python":
        children = ast.parse(source).body
    else:
        grammar = (tree_sitter_java.language() if language == "java"
                   else tree_sitter_typescript.language_typescript())
        tree = Parser(Language(grammar)).parse(source.encode("utf-8"))
        if tree.root_node.has_error:
            raise ValueError(f"invalid {language} syntax")
        children = tree.root_node.named_children
    for depth, name in enumerate(class_path.split(".")):
        matches = []
        for node in children:
            if language == "python":
                if isinstance(node, ast.ClassDef) and node.name == name:
                    matches.append(node)
                continue
            if language == "typescript" and depth == 0:
                if node.type != "export_statement":
                    continue
                node = node.child_by_field_name("declaration")
            if node is None or node.type != "class_declaration":
                continue
            if node.child_by_field_name("name").text.decode() != name:
                continue
            if language != "java" or "public" in modifiers(node):
                matches.append(node)
        if len(matches) != 1:
            raise ValueError(f"expected one public class {class_path}")
        node = matches[0]
        children = (node.body if language == "python"
                    else node.child_by_field_name("body").named_children)
    return children


def public_declarations(language, source, class_path):
    """Return public constructors, static factories and instance methods."""
    declarations = []
    for node in class_members(language, source, class_path):
        if language == "python":
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = {item.id for item in node.decorator_list if isinstance(item, ast.Name)}
            if "property" in decorators:
                continue
            kind = "static" if decorators & {"staticmethod", "classmethod"} else "instance"
            if node.name == "__init__":
                kind = "constructor"
            elif node.name.startswith("_"):
                continue
            declarations.append((kind, node.name, node))
            continue
        if node.type not in {"constructor_declaration", "method_declaration", "method_definition"}:
            continue
        flags = modifiers(node)
        if flags & {"private", "protected", "get", "set"}:
            continue
        if language == "java" and "public" not in flags:
            continue
        name = node.child_by_field_name("name").text.decode()
        if node.type == "constructor_declaration" or name == "constructor":
            kind = "constructor"
        elif "static" in flags:
            kind = "static"
        else:
            kind = "instance"
        declarations.append((kind, name, node))
    return declarations


def public_methods(language, source, class_name):
    """Parse instance declarations, excluding comments and unrelated classes."""
    return {name for kind, name, _ in public_declarations(language, source, class_name)
            if kind == "instance"}


def parameter_shape(language, node):
    if language == "python":
        args = node.args
        if args.vararg or args.kwarg or args.kwonlyargs or args.posonlyargs:
            raise ValueError("construction parameter form requires an updated contract")
        positional = args.args
        required = len(positional) - len(args.defaults)
        is_static = any(isinstance(item, ast.Name) and item.id == "staticmethod"
                        for item in node.decorator_list)
        if not is_static:
            if not positional:
                raise ValueError("instance construction member requires a receiver")
            positional = positional[1:]
            required = max(0, required - 1)
        return {"parameters": [item.arg for item in positional],
                "required": required}
    names = []
    required = 0
    for parameter in node.child_by_field_name("parameters").named_children:
        if parameter.type in {"line_comment", "block_comment", "comment"}:
            continue
        name = parameter.child_by_field_name("name" if language == "java" else "pattern")
        if name is None:
            raise ValueError("unsupported construction parameter")
        names.append(name.text.decode())
        if parameter.type != "optional_parameter" and parameter.child_by_field_name("value") is None:
            required += 1
    return {"parameters": names, "required": required}


def check_construction(contract, language, source):
    """Check constructor parameter shapes and fluent Builder declarations."""
    binding = contract["clients"][language]
    members = public_declarations(language, source, binding["type"])
    actual = [parameter_shape(language, node) for kind, _, node in members if kind == "constructor"]
    actual_shapes = sorted(json.dumps(row, sort_keys=True) for row in actual)
    expected_shapes = sorted(json.dumps(row, sort_keys=True) for row in binding["constructors"])
    if actual_shapes != expected_shapes:
        raise ValueError(f"{language}: constructor parameters or required arguments differ")
    builder = public_declarations(language, source, binding["builderType"])
    checks = [(members, "static", binding["builderFactory"], []),
              (builder, "instance", binding["build"], [])]
    for field in contract["fields"]:
        if language not in field["bindings"]:
            continue
        name = field["bindings"][language]
        expected = (re.sub(r"(?<!^)(?=[A-Z])", "_", field["id"]).lower()
                    if language == "python" else field["id"])
        if name != expected:
            raise ValueError(f"{language}: unexpected Builder mapping for {field['id']}")
        checks.append((builder, "instance", name, ["value" if language == "typescript" else name]))
    for declarations, kind, name, parameters in checks:
        matches = [node for candidate_kind, candidate_name, node in declarations
                   if candidate_kind == kind and candidate_name == name]
        expected = {"parameters": parameters, "required": len(parameters)}
        if len(matches) != 1 or parameter_shape(language, matches[0]) != expected:
            raise ValueError(f"{language}: missing or unexpected construction member {name}")
    return len(actual) + len(checks)


def check_contract(contract, language, source):
    """Validate declared availability as well as canonical language name mappings."""
    class_name = contract["clients"][language].rsplit(".", 1)[-1]
    methods = public_methods(language, source, class_name)
    checked = 0
    unavailable = 0
    for operation in contract["operations"]:
        operation_id = operation["id"]
        expected = (re.sub(r"(?<!^)(?=[A-Z])", "_", operation_id).lower()
                    if language == "python" else operation_id)
        actual = operation["bindings"][language]
        if actual != expected:
            raise ValueError(f"{language}: {operation_id} maps to {actual}, expected {expected}")
        implemented = operation["implementedIn"]
        if (len(implemented) != len(set(implemented))
                or not set(implemented) <= {"go", *LANGUAGES}
                or "go" not in implemented):
            raise ValueError(f"invalid implementation scope for {operation_id}")
        if language in implemented:
            if actual not in methods:
                raise ValueError(f"{language}: missing public instance method {class_name}.{actual}")
            checked += 1
        else:
            if actual in methods:
                raise ValueError(f"{language}: update implementation scope for {operation_id}")
            unavailable += 1
    return checked, unavailable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=LANGUAGES, required=True)
    parser.add_argument("--repo", type=Path, required=True, help="read-only SDK checkout root")
    args = parser.parse_args(argv)
    try:
        contract = json.loads((ROOT / "contracts/pam-api.json").read_text(encoding="utf-8"))
        baseline = json.loads((ROOT / "contracts/cross-repo-baselines.json").read_text(encoding="utf-8"))
        repo = args.repo.resolve()
        source = (repo / baseline[args.language]["source"]).resolve()
        if not source.is_relative_to(repo):
            raise ValueError("source must remain inside the SDK checkout")
        source_text = source.read_text(encoding="utf-8")
        checked, unavailable = check_contract(contract, args.language, source_text)
        construction = json.loads((ROOT / "contracts/pam-construction.json").read_text(encoding="utf-8"))
        if (construction["schemaVersion"] != 1
                or construction["clients"][args.language]["type"] != contract["clients"][args.language].rsplit(".", 1)[-1]):
            raise ValueError("invalid construction contract identity")
        construction_checked = check_construction(construction, args.language, source_text)
    except (OSError, ValueError, KeyError, SyntaxError) as error:
        print(f"Contract check failed: {error}", file=sys.stderr)
        return 1
    print(f"{args.language}: verified {checked} public method names; {unavailable} not implemented; "
          f"verified {construction_checked} construction members")
    return 0


if __name__ == "__main__":
    sys.exit(main())
