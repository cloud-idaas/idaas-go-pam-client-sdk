"""Regression tests for declaration-based public API name checks."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_cross_repo_contract as checker


SOURCES = {
    "java": '''
        public class IDaaSPamClient {
            public IDaaSPamClient() {}
            public IDaaSPamClient(String developerApiEndpoint, String idaasInstanceId, Object credentialProvider) {}
            public static IDaaSPamClientBuilder builder() { return null; }
            public static final class IDaaSPamClientBuilder {
                public IDaaSPamClientBuilder developerApiEndpoint(String developerApiEndpoint) { return this; }
                public IDaaSPamClientBuilder idaasInstanceId(String idaasInstanceId) { return this; }
                public IDaaSPamClientBuilder credentialProvider(Object credentialProvider) { return this; }
                public IDaaSPamClient build() { return null; }
            }
            // public String commented() { return ""; }
            public String getApiKey(String identifier) { return "fake()"; }
            public String getApiKey(String identifier, Object options) { return ""; }
            private void hidden() {}
            protected void inherited() {}
            void packageOnly() {}
            public static void factory() {}
            class Inner { public void nested() {} }
        }
        class Other { public void unrelated() {} }
    ''',
    "python": '''
class IDaaSPamClient:
    def __init__(self, developer_api_endpoint=None, idaas_instance_id=None, credential_provider=None): pass
    @staticmethod
    def builder(): return IDaaSPamClient.IDaaSPamClientBuilder()
    class IDaaSPamClientBuilder:
        def developer_api_endpoint(self, developer_api_endpoint): return self
        def idaas_instance_id(self, idaas_instance_id): return self
        def credential_provider(self, credential_provider): return self
        def build(self): return IDaaSPamClient()
    # def commented(self): pass
    def get_api_key(self, identifier):
        return "def fake(self): pass"
    async def async_method(self): pass
    def _hidden(self): pass
    @staticmethod
    def factory(): pass
    @classmethod
    def factory2(cls): pass
    @property
    def value(self): pass
    class Inner:
        def nested(self): pass
class Other:
    def unrelated(self): pass
''',
    "typescript": '''
        export class IDaaSPamClient {
            // async commented() {}
            async getApiKey(identifier: string): Promise<string> { return "fake()"; }
            private hidden() {}
            protected inherited() {}
            static factory() {}
            get value(): string { return ""; }
            set value(input: string) {}
            constructor(private readonly options: object = {}) {}
            static builder(): PamClientBuilder { return new PamClientBuilder(); }
        }
        export class PamClientBuilder {
            developerApiEndpoint(value: string): this { return this; }
            idaasInstanceId(value: string): this { return this; }
            credentialProvider(value: object): this { return this; }
            httpClient(value: object): this { return this; }
            build(): IDaaSPamClient { return new IDaaSPamClient(); }
        }
        export class Other { unrelated() {} }
    ''',
}


def contract():
    return {
        "clients": {"java": "com.cloud_idaas.pam.IDaaSPamClient",
                    "python": "cloud_idaas.pam_client.IDaaSPamClient",
                    "typescript": "IDaaSPamClient"},
        "operations": [
            {"id": "getApiKey", "bindings": {"java": "getApiKey",
             "python": "get_api_key", "typescript": "getApiKey"},
             "implementedIn": ["go", *checker.LANGUAGES]},
            {"id": "obtainAccessCredential", "bindings": {
             "java": "obtainAccessCredential", "python": "obtain_access_credential",
             "typescript": "obtainAccessCredential"}, "implementedIn": ["go"]},
        ],
    }


def construction_contract():
    path = Path(__file__).resolve().parent.parent / "contracts/pam-construction.json"
    return json.loads(path.read_text(encoding="utf-8"))


class PublicNamesTests(unittest.TestCase):
    def test_only_direct_public_instance_declarations_count(self):
        for language, source in SOURCES.items():
            with self.subTest(language=language):
                expected = ({"get_api_key", "async_method"} if language == "python"
                            else {"getApiKey"})
                self.assertEqual(checker.public_methods(language, source, "IDaaSPamClient"), expected)

    def test_invalid_syntax_and_wrong_class_fail(self):
        for language, source in SOURCES.items():
            with self.subTest(language=language):
                with self.assertRaises((SyntaxError, ValueError)):
                    checker.public_methods(language, "class {", "IDaaSPamClient")
                with self.assertRaises(ValueError):
                    checker.public_methods(language, source, "MissingClient")

    def test_nonpublic_client_class_fails(self):
        for language, source in (("java", "class IDaaSPamClient {}"),
                                 ("typescript", "class IDaaSPamClient {}")):
            with self.subTest(language=language), self.assertRaises(ValueError):
                checker.public_methods(language, source, "IDaaSPamClient")

    def test_existing_and_unimplemented_names_are_reported_separately(self):
        for language, source in SOURCES.items():
            with self.subTest(language=language):
                self.assertEqual(checker.check_contract(contract(), language, source), (1, 1))

    def test_misspelled_binding_fails_even_when_unimplemented(self):
        for language in checker.LANGUAGES:
            for operation_index in (0, 1):
                with self.subTest(language=language, operation=operation_index):
                    data = contract()
                    data["operations"][operation_index]["bindings"][language] = "IntentionallyMissingPublicMethod"
                    with self.assertRaisesRegex(ValueError, "expected"):
                        checker.check_contract(data, language, SOURCES[language])

    def test_removed_method_fails(self):
        for language, source in SOURCES.items():
            name = contract()["operations"][0]["bindings"][language]
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "missing public"):
                checker.check_contract(contract(), language, source.replace(name, "renamed"))

    def test_newly_implemented_method_requires_scope_update(self):
        for language, source in SOURCES.items():
            data = contract()
            data["operations"][0]["implementedIn"] = ["go"]
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "update implementation"):
                checker.check_contract(data, language, source)

    def test_invalid_scope_fails(self):
        for scope in (["go", "go"], ["go", "unknown"], ["java"]):
            data = contract()
            data["operations"][0]["implementedIn"] = scope
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, "invalid implementation"):
                checker.check_contract(data, "java", SOURCES["java"])

    def test_cli_success_and_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "contracts").mkdir()
            (root / "contracts/pam-api.json").write_text(json.dumps(contract()), encoding="utf-8")
            (root / "contracts/pam-construction.json").write_text(json.dumps(construction_contract()), encoding="utf-8")
            baselines = {"java": {"source": "Client.java"}}
            baseline_file = root / "contracts/cross-repo-baselines.json"
            baseline_file.write_text(json.dumps(baselines), encoding="utf-8")
            repo = root / "repo"
            repo.mkdir()
            (repo / "Client.java").write_text(SOURCES["java"], encoding="utf-8")
            args = ["--language", "java", "--repo", str(repo)]
            with patch.object(checker, "ROOT", root):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(checker.main(args), 0)
                self.assertIn("verified 1 public method names; 1 not implemented", output.getvalue())
                for path in ("Missing.java", "../outside.java"):
                    data = deepcopy(baselines)
                    data["java"]["source"] = path
                    baseline_file.write_text(json.dumps(data), encoding="utf-8")
                    output = io.StringIO()
                    with redirect_stderr(output):
                        self.assertEqual(checker.main(args), 1)
                    self.assertIn("Contract check failed:", output.getvalue())
                baseline_file.write_text(json.dumps(baselines), encoding="utf-8")
                data = construction_contract()
                data["clients"]["java"]["type"] = "Other"
                (root / "contracts/pam-construction.json").write_text(json.dumps(data), encoding="utf-8")
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(checker.main(args), 1)


class ConstructionTests(unittest.TestCase):
    def test_constructor_and_builder_declarations_match(self):
        for language, count in (("java", 7), ("python", 6), ("typescript", 7)):
            with self.subTest(language=language):
                self.assertEqual(checker.check_construction(construction_contract(), language, SOURCES[language]), count)

    def test_python_receivers_are_distinguished_from_static_arguments(self):
        source = SOURCES["python"]
        self.assertEqual(checker.check_construction(construction_contract(), "python",
                         source.replace("def build(self)", "def build(this)")), 6)
        for old, new in (("def builder()", "def builder(self)"),
                         ("def build(self)", "def build()")):
            with self.subTest(method=old), self.assertRaises(ValueError):
                checker.check_construction(construction_contract(), "python", source.replace(old, new))

    def test_constructor_parameter_or_default_changes_fail(self):
        changes = {"java": ("String idaasInstanceId", "String instance"),
                   "python": ("developer_api_endpoint=None", "developer_api_endpoint"),
                   "typescript": ("options: object = {}", "options: object")}
        for language, (old, new) in changes.items():
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "constructor parameters"):
                checker.check_construction(construction_contract(), language, SOURCES[language].replace(old, new, 1))

    def test_renamed_factory_or_builder_method_fails(self):
        changes = {"java": ("credentialProvider(Object credentialProvider)", "renamedProvider(Object credentialProvider)"),
                   "python": ("def credential_provider(self, credential_provider)", "def renamed_provider(self, credential_provider)"),
                   "typescript": ("credentialProvider(value: object)", "renamedProvider(value: object)")}
        for language, (old, new) in changes.items():
            for source in (SOURCES[language].replace(old, new), SOURCES[language].replace("builder()", "createBuilder()")):
                with self.subTest(language=language), self.assertRaisesRegex(ValueError, "construction member"):
                    checker.check_construction(construction_contract(), language, source)

    def test_wrong_builder_mapping_fails(self):
        for language in checker.LANGUAGES:
            data = construction_contract()
            data["fields"][0]["bindings"][language] = "unrelated"
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "Builder mapping"):
                checker.check_construction(data, language, SOURCES[language])

    def test_changed_setter_arguments_fail(self):
        changes = {"java": ("credentialProvider(Object credentialProvider)", "credentialProvider(Object credentialProvider, Object extra)"),
                   "python": ("def credential_provider(self, credential_provider)", "def credential_provider(self, credential_provider=None)"),
                   "typescript": ("credentialProvider(value: object)", "credentialProvider(value?: object)")}
        for language, (old, new) in changes.items():
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "construction member"):
                checker.check_construction(construction_contract(), language, SOURCES[language].replace(old, new))

    def test_static_or_private_setters_do_not_satisfy_contract(self):
        changes = {"java": ("public IDaaSPamClientBuilder credentialProvider", "public static IDaaSPamClientBuilder credentialProvider"),
                   "python": ("        def credential_provider", "        @staticmethod\n        def credential_provider"),
                   "typescript": ("            credentialProvider", "            private credentialProvider")}
        for language, (old, new) in changes.items():
            with self.subTest(language=language), self.assertRaisesRegex(ValueError, "construction member"):
                checker.check_construction(construction_contract(), language, SOURCES[language].replace(old, new))

    def test_changed_parameter_forms_require_contract_review(self):
        changes = {"java": ("String developerApiEndpoint, String idaasInstanceId, Object credentialProvider", "Object... args"),
                   "python": ("developer_api_endpoint=None, idaas_instance_id=None, credential_provider=None", "*args")}
        for language, (old, new) in changes.items():
            with self.subTest(language=language), self.assertRaises(ValueError):
                checker.check_construction(construction_contract(), language, SOURCES[language].replace(old, new, 1))


if __name__ == "__main__":
    unittest.main()
