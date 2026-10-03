import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "fritz_h0_d1o_nametable_provenance.py"
SPEC = importlib.util.spec_from_file_location("d1o", SCRIPT)
d1o = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(d1o)


class D1oTests(unittest.TestCase):
    def test_struct_definition_candidate(self):
        r = d1o.analyze_text(r'''
static struct mtd_entry nametable[] = {
  { "rootfs", "filesystem", "filesystem2" },
};
''')
        self.assertEqual(r["nametableIdentifierCount"], 1)
        self.assertEqual(r["declarationCandidateCount"], 1)
        self.assertEqual(r["initializerCandidateCount"], 1)
        self.assertEqual(r["bracedInitializerCandidateCount"], 1)
        self.assertEqual(r["mtdEntryDeclarationCandidateCount"], 1)
        self.assertEqual(r["mtdEntryInitializerCandidateCount"], 1)
        self.assertEqual(r["declarationCandidates"][0]["typeIdentifier"], "mtd_entry")

    def test_extern_declaration_candidate(self):
        r = d1o.analyze_text("extern struct mtd_entry *nametable;")
        self.assertEqual(r["externDeclarationCandidateCount"], 1)
        self.assertEqual(r["initializerCandidateCount"], 0)

    def test_downstream_use_is_not_declaration_candidate(self):
        r = d1o.analyze_text(
            "new_name = linux_fs_start ? nametable[i].runtime_name_1 : nametable[i].runtime_name_0;"
        )
        self.assertEqual(r["nametableIdentifierCount"], 2)
        self.assertEqual(r["declarationCandidateCount"], 0)

    def test_comments_and_strings_do_not_count(self):
        r = d1o.analyze_text(
            '/* nametable */ const char *x = "nametable";'
        )
        self.assertEqual(r["nametableIdentifierCount"], 0)
        self.assertEqual(r["declarationCandidateCount"], 0)

    def test_classification_prefers_strongest_shape(self):
        self.assertEqual(
            d1o.classify({"hits": [{
                "nametableIdentifierCount": 1,
                "declarationCandidateCount": 1,
                "initializerCandidateCount": 1,
                "bracedInitializerCandidateCount": 1,
                "mtdEntryDeclarationCandidateCount": 1,
                "mtdEntryInitializerCandidateCount": 1,
                "mtdEntryBracedInitializerCandidateCount": 1,
            }]}),
            "H0_D1O_MTD_ENTRY_BRACED_DEFINITION_CANDIDATE_LOCATED",
        )


if __name__ == "__main__":
    unittest.main()
