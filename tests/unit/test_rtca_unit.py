import os
import tempfile
import shutil
import pytest

# Import your RTCA main functions
from postprocessor import rtca

# Dummy WhitelistDB for testing (no real DB access)
class DummyWhitelistDB:
    def __init__(self):
        self.hashes = set()
    def is_whitelisted_hash(self, file_hash):
        return file_hash in self.hashes
    def add_hash(self, file_hash, path):
        self.hashes.add(file_hash)
        return True

@pytest.fixture
def dummy_whitelist():
    return DummyWhitelistDB()

def make_temp_file(content, ext):
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.' + ext)
    tf.write(content)
    tf.flush()
    tf.close()
    return tf.name

def test_jpg_magic_and_whitelist(dummy_whitelist):
    # Valid JPG magic number
    jpg_content = b'\xff\xd8\xff' + b'fakejpgdata'
    path = make_temp_file(jpg_content, "jpg")
    # Not whitelisted initially
    result = rtca.rtca_analyze(path, dummy_whitelist, debug=True)
    assert result == "auto-whitelisted"
    # Should now be whitelisted
    result2 = rtca.rtca_analyze(path, dummy_whitelist)
    assert result2 == "auto-whitelisted"
    os.unlink(path)

def test_jpg_magic_mismatch(dummy_whitelist):
    # Wrong magic number for jpg (should fail magic check)
    bad_content = b'\x00\x11\x22\x33'
    path = make_temp_file(bad_content, "jpg")
    result = rtca.rtca_analyze(path, dummy_whitelist, debug=True)
    assert result == "suspicious"
    os.unlink(path)

def test_unknown_extension_flags_suspicious(dummy_whitelist):
    # File with unknown extension (no analyzer)
    content = b'some content'
    path = make_temp_file(content, "notreal")
    result = rtca.rtca_analyze(path, dummy_whitelist, debug=True)
    assert result == "suspicious"
    os.unlink(path)

def test_recursion_depth_limit(dummy_whitelist, monkeypatch):
    # Create a zip file that contains itself (simulate depth limit)
    import zipfile
    tmp_dir = tempfile.mkdtemp()
    inner_zip_path = os.path.join(tmp_dir, "inner.zip")
    # Create dummy zip
    with zipfile.ZipFile(inner_zip_path, "w") as zf:
        zf.writestr("file.txt", b"dummy")
    # Now nest the same zip inside itself
    with zipfile.ZipFile(inner_zip_path, "a") as zf:
        with open(inner_zip_path, "rb") as f:
            zf.writestr("nested.zip", f.read())

    # Patch max_depth to a low number for test
    result = rtca.rtca_analyze(inner_zip_path, dummy_whitelist, max_depth=0, debug=True)
    assert result == "suspicious"
    shutil.rmtree(tmp_dir)

def test_hash_whitelisting(dummy_whitelist):
    # Create a file, compute its hash, manually whitelist it
    content = b'important data'
    path = make_temp_file(content, "bin")
    file_hash = rtca.compute_file_hash(path)
    dummy_whitelist.add_hash(file_hash, path)
    result = rtca.rtca_analyze(path, dummy_whitelist, debug=True)
    assert result == "auto-whitelisted"
    os.unlink(path)
