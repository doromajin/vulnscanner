"""PHAST-UPLOAD-001: uploaded file stored under a client-chosen extension (CWE-434).

TP cases must keep firing; safe cases (server-chosen name/extension, allow-list on the
extension) must stay quiet so the rule cannot turn into a blanket 'any move()' flag."""
import pytest

from vulnscanner.analyzers.ast_php import PhpASTAnalyzer
from vulnscanner.models import Severity


def _scan(body: str):
    code = "<?php\nclass C {\n    public function up($request, $file)\n    {\n" + body + "\n    }\n}\n"
    return [f for f in PhpASTAnalyzer().analyze("app/Http/C.php", code)
            if f.rule_id == "PHAST-UPLOAD-001"]


class TestUploadDetected:
    @pytest.mark.parametrize("body", [
        # Laravel: extension from the client, moved into public/
        "$n = md5(time()) . '.' . strtolower($file->getClientOriginalExtension());\n"
        "        $file->move(public_path('uploads'), $n);",
        # same, inline in the call and through a request->file() chain
        "$request->file('img')->move(public_path() . '/up', 'a.' . $request->file('img')->getClientOriginalExtension());",
        # original name is just as client-controlled
        "$file->move(public_path('up'), $file->getClientOriginalName());",
        # a name built over several assignments
        "$ext = $file->getClientOriginalExtension();\n        $base = 'x-' . $request->id;\n"
        "        $full = $base . '.' . $ext;\n        $file->move(public_path('up'), $full);",
        # Storage helpers
        "$file->storeAs('docs', $file->getClientOriginalName(), 'public');",
        "Storage::putFileAs('docs', $file, $file->getClientOriginalName());",
        # plain PHP
        "move_uploaded_file($_FILES['f']['tmp_name'], $_SERVER['DOCUMENT_ROOT'] . '/up/' . $_FILES['f']['name']);",
        # slug() on the name does not neutralise the client extension
        "$file->move(public_path('up'), Str::slug($request->title) . '.' . $file->getClientOriginalExtension());",
        # pathinfo(.., PATHINFO_EXTENSION) hands the extension straight through
        "$file->move(public_path('up'), 'a.' . pathinfo($file->getClientOriginalName(), PATHINFO_EXTENSION));",
    ])
    def test_client_extension_flagged(self, body):
        assert _scan(body)

    def test_web_served_directory_is_high(self):
        f = _scan("$file->move(public_path('up'), 'a.' . $file->getClientOriginalExtension());")
        assert [x.severity for x in f] == [Severity.HIGH]

    def test_private_directory_is_medium(self):
        f = _scan("$file->move(storage_path('app/private'), 'a.' . $file->getClientOriginalExtension());")
        assert [x.severity for x in f] == [Severity.MEDIUM]


class TestUploadSafe:
    @pytest.mark.parametrize("body", [
        # extension derived from the content type
        "$file->move(public_path('up'), md5(time()) . '.' . $file->guessExtension());",
        "$file->move(public_path('up'), md5(time()) . '.' . $file->extension());",
        "$file->storeAs('docs', $file->hashName(), 'public');",
        # fixed suffix, client value never reaches the name
        "$file->move(public_path('up'), md5(time()) . '.jpg');",
        "move_uploaded_file($_FILES['f']['tmp_name'], '/srv/up/' . uniqid() . '.dat');",
        # a plain move() of a non-upload path
        "$tmp->move($dest, 'archive.zip');",
        # client name reduced to a slug of its base name, fixed extension
        "$n = 'u-' . Str::slug(pathinfo($file->getClientOriginalName(), PATHINFO_FILENAME)) . '.zip';\n"
        "        Storage::putFileAs('app/backups', $file, $n);",
        # client name hashed, fixed extension
        "$file->move(public_path('up'), md5($file->getClientOriginalName()) . '.jpg');",
    ])
    def test_server_chosen_name_not_flagged(self, body):
        assert not _scan(body)

    @pytest.mark.parametrize("body", [
        "$ext = strtolower($file->getClientOriginalExtension());\n"
        "        if (!in_array($ext, ['jpg', 'png'], true)) { return; }\n"
        "        $file->move(public_path('up'), 'a.' . $ext);",
        "if (!in_array(strtolower($file->getClientOriginalExtension()), ['jpg'])) { return; }\n"
        "        $file->move(public_path('up'), 'a.' . $file->getClientOriginalExtension());",
        "if (!preg_match('/\\.(jpg|png)$/i', $file->getClientOriginalName())) { return; }\n"
        "        $file->move(public_path('up'), $file->getClientOriginalName());",
        "$request->validate(['f' => 'required|extensions:jpg,png']);\n"
        "        $file->move(public_path('up'), $file->getClientOriginalName());",
        # suffix match against an allow-list (extension comes from the list)
        "$orig = $file->getClientOriginalName();\n"
        "        foreach (['.pdf', '.png'] as $ext) {\n"
        "            if (substr_compare($orig, $ext, -strlen($ext)) === 0) { $found = $ext; break; }\n"
        "        }\n"
        "        $file->move(public_path('up'), 'f' . $found . $orig);",
        "if (!str_ends_with($file->getClientOriginalName(), '.pdf')) { return; }\n"
        "        $file->move(public_path('up'), $file->getClientOriginalName());",
    ])
    def test_extension_allowlist_suppresses(self, body):
        assert not _scan(body)

    def test_allowlist_in_another_function_does_not_suppress(self):
        code = (
            "<?php\nclass C {\n"
            "    public function ok($file) {\n"
            "        if (!in_array($file->getClientOriginalExtension(), ['jpg'])) { return; }\n"
            "    }\n"
            "    public function bad($file) {\n"
            "        $file->move(public_path('up'), $file->getClientOriginalName());\n"
            "    }\n}\n"
        )
        f = [x for x in PhpASTAnalyzer().analyze("a.php", code) if x.rule_id == "PHAST-UPLOAD-001"]
        assert [x.line_number for x in f] == [7]
