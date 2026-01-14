import os
import tempfile
import shutil
import pytest

from postprocessor.whitelist import WhitelistDB

@pytest.fixture
def temp_db():
    tmpdir = tempfile.mkdtemp()
    db_path = os.path.join(tmpdir, "test_whitelist.sqlite")
    db = WhitelistDB(db_path, debug=True)
    yield db
    db.close()
    shutil.rmtree(tmpdir)

def test_add_and_check_hash(temp_db):
    h1 = "abc123"
    assert not temp_db.is_whitelisted_hash(h1)
    temp_db.add_hash(h1)
    assert temp_db.is_whitelisted_hash(h1)

def test_add_path_and_get_paths(temp_db):
    h = "fff111"
    p1 = "/path/to/file1"
    p2 = "/another/path/file1"
    temp_db.add_hash(h)
    temp_db.add_path(h, p1)
    temp_db.add_path(h, p2)
    paths = temp_db.get_paths(h)
    assert p1 in paths
    assert p2 in paths
    assert len(paths) == 2

def test_metadata_storage_and_retrieval(temp_db):
    h = "beefcafe"
    meta = {"foo": "bar", "count": 7}
    temp_db.add_hash(h, metadata=meta)
    stored = temp_db.get_metadata(h)
    assert stored["foo"] == "bar"
    assert stored["count"] == 7

def test_relationships(temp_db):
    p, c = "parenthash", "childhash"
    temp_db.add_hash(p)
    temp_db.add_hash(c)
    temp_db.add_relationship(p, c)
    # Directly check the underlying DB for relationship
    rels = temp_db.conn.execute("SELECT parent_hash, child_hash FROM relationships").fetchall()
    assert (p, c) in rels

def test_remove_hash(temp_db):
    h = "deadbeef"
    p1 = "/x"
    temp_db.add_hash(h)
    temp_db.add_path(h, p1)
    temp_db.remove_hash(h)
    assert not temp_db.is_whitelisted_hash(h)
    assert temp_db.get_paths(h) == []
    # No relationship should exist
    rels = temp_db.conn.execute("SELECT * FROM relationships WHERE parent_hash=? OR child_hash=?", (h, h)).fetchall()
    assert rels == []

def test_duplicate_hash_and_path(temp_db):
    h = "duphash"
    p = "/dup/path"
    temp_db.add_hash(h)
    temp_db.add_hash(h)  # Should not error or duplicate
    temp_db.add_path(h, p)
    temp_db.add_path(h, p)  # Should not duplicate
    paths = temp_db.get_paths(h)
    assert paths.count(p) == 1

