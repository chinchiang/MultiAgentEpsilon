"""封存展開與二進位審查清單的純函式檢查：不需 gitleaks，測試 ID 固定，供突變測試使用。

Pure-function checks of archive expansion and the binary allowlist: no gitleaks binary and fixed test IDs, so the
mutation campaign can use them."""
import gzip
import hashlib
import io
import json
import re
import struct
import tarfile
import zipfile
import zlib
from dataclasses import replace

import pytest

from security_harness.limits import LIMITS, ResourceLimit
from security_harness.scan_content import (ContentInventory, UnsupportedContent, is_text, load_binary_allowlist,
                                           zip_central, zip_extra, zip_payloads)

# 固定時間戳，讓產生的封存每次位元組相同。 / A fixed timestamp keeps generated archives byte-identical.
STAMP = (2026, 1, 1, 0, 0, 0)


def refused(message):
    return pytest.raises(UnsupportedContent, match='^' + re.escape(message) + '$')


def limited(message):
    return pytest.raises(ResourceLimit, match='^' + re.escape(message) + '$')


def zipped(*members, comment=b'', compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=compression) as output:
        for item, data in members:
            if isinstance(item, str):
                item = zipfile.ZipInfo(item, STAMP)
                item.compress_type = compression
            output.writestr(item, data)
        output.comment = comment
    return stream.getvalue()


def info(name, **fields):
    item = zipfile.ZipInfo(name, STAMP)
    for key, value in fields.items():
        setattr(item, key, value)
    return item


def tarred(*members, trailer=b''):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as output:
        for name, data, kind in members:
            item = tarfile.TarInfo(name)
            item.type, item.size, item.mtime = kind, len(data), 0
            output.addfile(item, io.BytesIO(data))
    return stream.getvalue() + trailer


def gzip_with(flags, field=b'', body=b'synthetic'):
    data = gzip.compress(body, mtime=0)
    return data[:3] + bytes([flags]) + data[4:10] + field + data[10:]


def add(tmp_path, data, **kwargs):
    inventory = ContentInventory(tmp_path, **kwargs)
    inventory.add(data, 'bundle.bin', scope='worktree')
    return inventory


def files(inventory):
    return sorted(entry['file'] for entry in inventory.entries.values())


# 二進位審查清單 / Binary allowlist

def write_allowlist(tmp_path, document):
    path = tmp_path / 'allowlist.json'
    path.write_text(json.dumps(document))
    return path


def test_missing_allowlist_approves_nothing(tmp_path):
    assert load_binary_allowlist(tmp_path / 'absent.json') == frozenset()


def test_valid_allowlist_returns_each_reviewed_digest(tmp_path):
    entries = [{'sha256': 'a' * 64, 'reason': 'reviewed'}, {'sha256': 'b' * 64, 'reason': 'reviewed'}]
    path = write_allowlist(tmp_path, {'schema_version': 1, 'entries': entries})
    assert load_binary_allowlist(path) == frozenset({'a' * 64, 'b' * 64})


GOOD_ENTRY = {'sha256': 'a' * 64, 'reason': 'reviewed'}


@pytest.mark.parametrize('document', [
    [], {'entries': [GOOD_ENTRY]}, {'schema_version': True, 'entries': [GOOD_ENTRY]},
    {'schema_version': 2, 'entries': [GOOD_ENTRY]}, {'schema_version': 1, 'entries': {}},
    {'schema_version': 1, 'entries': ['a' * 64]}, {'schema_version': 1, 'entries': [{'sha256': 'a' * 64}]},
    {'schema_version': 1, 'entries': [{**GOOD_ENTRY, 'path': 'x'}]},
    {'schema_version': 1, 'entries': [{'sha256': 'A' * 64, 'reason': 'r'}]},
    {'schema_version': 1, 'entries': [{'sha256': 'a' * 64, 'reason': 1}]},
    {'schema_version': 1, 'entries': [{'sha256': 'a' * 64, 'reason': ' '}]},
    {'schema_version': 1, 'entries': [GOOD_ENTRY, GOOD_ENTRY]},
], ids=['not-object', 'no-schema', 'boolean-schema', 'schema-2', 'entries-object', 'entry-string', 'no-reason',
        'extra-key', 'uppercase-digest', 'reason-number', 'blank-reason', 'duplicate'])
def test_malformed_allowlist_is_refused(tmp_path, document):
    with pytest.raises(ValueError, match='^invalid binary allowlist$'):
        load_binary_allowlist(write_allowlist(tmp_path, document))


# 文字判定 / Text detection

@pytest.mark.parametrize('data, expected', [
    (b'plain text\n', True), (b'\xef\xbb\xbfbom text', True), (b'tab\tcarriage\r\nline', True), (b'', True),
    (b'\xff\xfe', False), (b'null\x00byte', False), (b'escape\x1b', False), (b'unit\x1fseparator', False),
], ids=['plain', 'bom', 'whitespace', 'empty', 'invalid-utf8', 'nul', 'escape', 'unit-separator'])
def test_text_detection(data, expected):
    assert is_text(data) is expected


# ZIP extra 欄位 / ZIP extra fields

@pytest.mark.parametrize('field', [
    b'', struct.pack('<HH', 0x5455, 13) + bytes(13), struct.pack('<HH', 0x0001, 28) + bytes(28),
    struct.pack('<HH', 0x5455, 5) + bytes(5) + struct.pack('<HH', 0x7875, 0),
], ids=['empty', 'timestamp-at-limit', 'zip64-at-limit', 'two-records'])
def test_known_extra_records_within_their_limits_are_accepted(field):
    assert zip_extra(field) is None


@pytest.mark.parametrize('field', [
    b'\x55\x54\x05', struct.pack('<HH', 0x5455, 14) + bytes(14), struct.pack('<HH', 0x9999, 0),
    struct.pack('<HH', 0x5455, 5) + bytes(4), struct.pack('<HH', 0x5455, 0) + b'\x00',
], ids=['short-header', 'timestamp-over-limit', 'unknown-tag', 'truncated-data', 'trailing-byte'])
def test_unknown_oversized_or_truncated_extra_records_are_refused(field):
    with refused('unsupported zip extra field'):
        zip_extra(field)


# ZIP 結構 / ZIP structure

def test_plain_zip_member_and_container_strings_are_both_leaves(tmp_path):
    inventory = add(tmp_path, zipped(('notes/readme.txt', b'synthetic text')))
    assert files(inventory) == ['bundle.bin!container-strings', 'bundle.bin!notes/readme.txt']
    assert (inventory.archives, inventory.members) == (1, 1)


def test_zip_comments_must_be_text(tmp_path):
    add(tmp_path, zipped(('a.txt', b'x'), comment=b'release notes'))
    add(tmp_path, zipped((info('a.txt', comment=b'member note'), b'x')))
    with refused('binary zip comment'):
        add(tmp_path, zipped(('a.txt', b'x'), comment=zlib.compress(b'hidden payload')))
    with refused('binary zip comment'):
        add(tmp_path, zipped((info('a.txt', comment=zlib.compress(b'hidden payload')), b'x')))


def test_bytes_after_the_end_record_are_refused(tmp_path):
    with refused('unaccounted zip bytes'):
        add(tmp_path, zipped(('a.txt', b'x')) + b'trailing')


def test_member_extra_field_in_local_and_central_headers_is_checked(tmp_path):
    bad = struct.pack('<HH', 0x9999, 4) + b'data'
    with refused('unsupported zip extra field'):
        add(tmp_path, zipped((info('a.txt', extra=bad), b'x')))


def test_unlisted_entry_before_the_first_listed_member_is_refused(tmp_path):
    data = zipped(('a.txt', b'x'))
    with refused('unaccounted zip bytes'):
        add(tmp_path, data[:30] + data)


def test_central_directory_entry_must_follow_the_last_member():
    data = zipped(('a.txt', b'x'))
    # zipfile 會先拒絕壞簽章，所以用有效封存的目錄資訊直接檢查。 / zipfile rejects a bad signature first, so check
    # directly against the valid archive's directory.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert len(zip_payloads(data, archive)) == 1
        changed = bytearray(data)
        start = changed.index(b'PK\x01\x02')
        changed[start + 3] = 9
        with refused('unaccounted zip bytes'):
            zip_central(bytes(changed), archive)


def test_gap_between_members_and_central_directory_is_refused(tmp_path):
    data = zipped(('a.txt', b'x'))
    start = data.index(b'PK\x01\x02')
    padded = bytearray(data[:start] + b'\x00' * 4 + data[start:])
    record = padded.index(b'PK\x05\x06')
    padded[record + 16:record + 20] = (start + 4).to_bytes(4, 'little')
    with refused('unaccounted zip bytes'):
        add(tmp_path, bytes(padded))


def unseekable_zip():
    class Unseekable(io.RawIOBase):
        def __init__(self):
            self.buffer = io.BytesIO()
        def writable(self):
            return True
        def write(self, data):
            return self.buffer.write(data)
    target = Unseekable()
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr(info('a.txt'), b'synthetic text')
        output.writestr(info('b.txt'), b'second text')
    return target.buffer.getvalue()


def test_data_descriptors_with_and_without_signature_are_accepted(tmp_path):
    data = unseekable_zip()
    assert b'PK\x07\x08' in data
    assert files(add(tmp_path, data)) == ['bundle.bin!a.txt', 'bundle.bin!b.txt', 'bundle.bin!container-strings']
    unsigned = bytearray(data)
    # 去掉每個資料描述元的簽章並修正偏移，模擬無簽章的 12 位元組描述元。 / Strip each descriptor signature and fix the
    # offsets, as a 12-byte unsigned descriptor.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
    removed = 0
    for member in members:
        at = unsigned.index(b'PK\x07\x08', member.header_offset - removed)
        del unsigned[at:at + 4]
        removed += 4
    central = unsigned.index(b'PK\x01\x02')
    position, shift = central, 0
    for member in members:
        unsigned[position + 42:position + 46] = (member.header_offset - shift).to_bytes(4, 'little')
        shift += 4
        names, extra, comment = (int.from_bytes(unsigned[position + o:position + o + 2], 'little') for o in (28, 30, 32))
        position += 46 + names + extra + comment
    record = unsigned.index(b'PK\x05\x06')
    unsigned[record + 16:record + 20] = central.to_bytes(4, 'little')
    assert files(add(tmp_path, bytes(unsigned))) == files(add(tmp_path, data))


def insert_before_member(data, index, inserted):
    """在第 index 個成員前插入位元組，並修正中央目錄與結尾紀錄的偏移。 / Insert bytes before member `index` and fix
    the central directory and end record offsets."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members, start_dir = archive.infolist(), archive.start_dir
    at = members[index].header_offset
    changed = bytearray(data[:at] + inserted + data[at:])
    position = start_dir + len(inserted)
    for member in members:
        if member.header_offset >= at:
            changed[position + 42:position + 46] = (member.header_offset + len(inserted)).to_bytes(4, 'little')
        names, extra, comment = (int.from_bytes(changed[position + o:position + o + 2], 'little') for o in (28, 30, 32))
        position += 46 + names + extra + comment
    record = changed.index(b'PK\x05\x06', position)
    changed[record + 16:record + 20] = (start_dir + len(inserted)).to_bytes(4, 'little')
    return bytes(changed)


def test_data_descriptor_followed_by_extra_bytes_is_refused(tmp_path):
    data = unseekable_zip()
    with refused('unaccounted zip bytes'):
        add(tmp_path, insert_before_member(data, 1, b'\x00'))
    with refused('unaccounted zip bytes'):
        add(tmp_path, insert_before_member(data, 1, bytes(4)))


def test_later_member_without_a_local_header_signature_is_refused(tmp_path):
    data = bytearray(zipped(('a.txt', b'x'), ('b.txt', b'y')))
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as archive:
        second = archive.infolist()[1].header_offset
    data[second + 3] = 9
    with refused('unaccounted zip bytes'):
        add(tmp_path, bytes(data))


def test_gap_before_a_later_member_is_refused(tmp_path):
    data = zipped(('a.txt', b'x'), ('b.txt', b'y'))
    with refused('unaccounted zip bytes'):
        add(tmp_path, insert_before_member(data, 1, b'\x00'))


def zip64_end_record():
    stream = io.BytesIO()
    limit = zipfile.ZIP_FILECOUNT_LIMIT
    zipfile.ZIP_FILECOUNT_LIMIT = 0
    try:
        with zipfile.ZipFile(stream, 'w') as output:
            output.writestr(info('a.txt'), 'synthetic')
    finally:
        zipfile.ZIP_FILECOUNT_LIMIT = limit
    return stream.getvalue()


def test_zip64_end_record_is_accepted_but_not_with_an_extensible_sector(tmp_path):
    data = zip64_end_record()
    assert add(tmp_path, data).archives == 1
    record = data.index(b'PK\x06\x06')
    # zipfile 自己會拒絕這些變體，所以用有效封存的目錄資訊直接檢查結構函式。 / zipfile rejects these variants itself,
    # so check the structure function directly against the valid archive's directory.
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert zip_central(data, archive) is None
        longer = bytearray(data)
        longer[record + 4:record + 12] = (45).to_bytes(8, 'little')
        with refused('unaccounted zip bytes'):
            zip_central(bytes(longer), archive)
        locator = bytearray(data)
        locator[record + 56:record + 60] = b'PK\x06\x08'
        with refused('unaccounted zip bytes'):
            zip_central(bytes(locator), archive)


def encrypted_flag(data):
    # zipfile 寫入時會清掉加密旗標，直接改本地與中央標頭。 / zipfile clears the encryption flag on write, so set it
    # in the local and central headers directly.
    changed = bytearray(data)
    changed[6] |= 1
    central = changed.index(b'PK\x01\x02')
    changed[central + 8] |= 1
    return bytes(changed)


def test_encrypted_and_symlink_members_are_refused(tmp_path):
    with refused('encrypted or symlink archive member'):
        add(tmp_path, encrypted_flag(zipped(('a.txt', b'x'), compression=zipfile.ZIP_STORED)))
    with refused('encrypted or symlink archive member'):
        add(tmp_path, zipped((info('link', external_attr=0o120777 << 16), b'target')))


def test_regular_file_mode_member_is_accepted(tmp_path):
    assert 'bundle.bin!a.txt' in files(add(tmp_path, zipped((info('a.txt', external_attr=0o100644 << 16), b'x'))))


def test_empty_directory_member_is_skipped_but_one_with_data_is_refused(tmp_path):
    inventory = add(tmp_path, zipped(('notes/', b''), ('notes/a.txt', b'x')))
    assert files(inventory) == ['bundle.bin!container-strings', 'bundle.bin!notes/a.txt']
    with refused('directory archive member carries data'):
        add(tmp_path, zipped(('notes/', b'payload'), compression=zipfile.ZIP_STORED))
    with refused('directory archive member carries data'):
        add(tmp_path, zipped(('notes/', b'payload-that-compresses' * 4)))


def deflated_directory(data):
    # zipfile 寫目錄時一律不壓縮；先以同長度檔名寫入壓縮內容，再把名稱改成目錄。 / zipfile always stores
    # directories, so write deflated content under a same-length file name, then rename it to a directory.
    return zipped(('notes', data)).replace(b'notes', b'note/')


def test_directory_member_size_boundaries(tmp_path):
    with zipfile.ZipFile(io.BytesIO(deflated_directory(b''))) as archive:
        assert [(m.is_dir(), m.file_size, m.compress_size) for m in archive.infolist()] == [(True, 0, 2)]
    # deflate 空內容為 2 位元組，屬可接受的空目錄。 / Deflating nothing yields 2 bytes: still an empty directory.
    assert add(tmp_path, deflated_directory(b'')).archives == 1
    with refused('directory archive member carries data'):
        add(tmp_path, zipped(('notes/', b'p'), compression=zipfile.ZIP_STORED))


def test_zip_member_size_boundary(tmp_path):
    small = replace(LIMITS, max_file_bytes=8)
    assert 'bundle.bin!a.txt' in files(add(tmp_path, zipped(('a.txt', b'x' * 8)), limits=small))
    with limited('archive member too large'):
        add(tmp_path, zipped(('a.txt', b'x' * 9)), limits=small)


# tar / tar archives

def test_tar_member_and_directory_are_expanded(tmp_path):
    inventory = add(tmp_path, tarred(('notes', b'', tarfile.DIRTYPE), ('notes/a.txt', b'synthetic', tarfile.REGTYPE)))
    assert files(inventory) == ['bundle.bin!container-strings', 'bundle.bin!notes/a.txt']


def test_tar_directory_with_data_non_regular_member_and_trailer_are_refused(tmp_path):
    with refused('directory archive member carries data'):
        add(tmp_path, tarred(('notes', b'payload', tarfile.DIRTYPE)))
    with refused('non-regular tar member'):
        add(tmp_path, tarred(('link', b'', tarfile.SYMTYPE)))
    with refused('data after tar end-of-archive'):
        add(tmp_path, tarred(('a.txt', b'x', tarfile.REGTYPE), trailer=b'hidden'))
    assert add(tmp_path, tarred(('a.txt', b'x', tarfile.REGTYPE), trailer=bytes(512))).archives == 1


def test_tar_member_size_boundary(tmp_path):
    small = replace(LIMITS, max_file_bytes=8)
    assert 'bundle.bin!a.txt' in files(add(tmp_path, tarred(('a.txt', b'x' * 8, tarfile.REGTYPE)), limits=small))
    with limited('tar member too large'):
        add(tmp_path, tarred(('a.txt', b'x' * 9, tarfile.REGTYPE)), limits=small)


def test_single_header_tar_at_the_size_boundary_is_a_tar(tmp_path):
    data = tarred(('a.txt', b'', tarfile.REGTYPE))[:512]
    assert files(add(tmp_path, data)) == ['bundle.bin!a.txt', 'bundle.bin!container-strings']


def test_short_data_with_ustar_marker_is_not_a_tar(tmp_path):
    data = b'a' * 257 + b'ustar'
    assert files(add(tmp_path, data)) == ['bundle.bin']


# gzip

def test_plain_gzip_and_zero_padding_are_accepted(tmp_path):
    assert files(add(tmp_path, gzip.compress(b'synthetic', mtime=0))) == [
        'bundle.bin!container-strings', 'bundle.bin!gzip']
    assert add(tmp_path, gzip.compress(b'synthetic', mtime=0) + bytes(8)).archives == 1


def test_gzip_name_and_comment_fields_must_be_printable(tmp_path):
    assert add(tmp_path, gzip_with(0x18, b'clean.txt\x00synthetic comment\x00')).archives == 1
    assert add(tmp_path, gzip_with(0x08, b'clean.txt\x00')).archives == 1
    assert add(tmp_path, gzip_with(0x10, b'comment\x00')).archives == 1
    with refused('binary gzip header field'):
        add(tmp_path, gzip_with(0x08, b'bad\x01name\x00'))
    with refused('binary gzip header field'):
        add(tmp_path, gzip_with(0x10, b'bad\x01comment\x00'))
    with refused('binary gzip header field'):
        add(tmp_path, gzip_with(0x08, b'no-terminator'))


@pytest.mark.parametrize('flags', [0x04, 0x20, 0x40, 0x80], ids=['extra', 'reserved-5', 'reserved-6', 'reserved-7'])
def test_gzip_extra_and_reserved_flags_are_refused(tmp_path, flags):
    with refused('unsupported gzip header'):
        add(tmp_path, gzip_with(flags))


def test_gzip_text_hint_flag_is_accepted(tmp_path):
    assert add(tmp_path, gzip_with(0x01)).archives == 1


def test_gzip_header_must_be_deflate_and_long_enough(tmp_path):
    data = gzip.compress(b'synthetic', mtime=0)
    with refused('unsupported gzip header'):
        add(tmp_path, data[:2] + b'\x07' + data[3:])
    with refused('unsupported gzip header'):
        add(tmp_path, data[:17])
    with refused('unsupported gzip header'):
        add(tmp_path, data[:3])
    # 18 位元組可通過標頭檢查，再由串流檢查拒絕。 / 18 bytes pass the header check and fail the stream check.
    with refused('unaccounted gzip bytes'):
        add(tmp_path, data[:18])


def test_corrupt_truncated_or_trailing_gzip_streams_are_refused(tmp_path):
    data = gzip.compress(b'synthetic', mtime=0)
    with refused('corrupt gzip stream'):
        add(tmp_path, data[:10] + b'\xff' * 8 + data[18:])
    with refused('unaccounted gzip bytes'):
        add(tmp_path, data[:-4])
    with refused('unaccounted gzip bytes'):
        add(tmp_path, data + b'trailing')
    with refused('unaccounted gzip bytes'):
        add(tmp_path, data + gzip.compress(b'second', mtime=0))


def test_gzip_expansion_stops_at_the_budget(tmp_path):
    small = replace(LIMITS, max_file_bytes=16, max_expanded_bytes=1024)
    assert add(tmp_path, gzip.compress(b'x' * 16, mtime=0), limits=small).expanded_bytes == 16
    with limited('expanded content byte limit exceeded'):
        add(tmp_path, gzip.compress(b'x' * 17, mtime=0), limits=small)
    # 剛好用完預算時仍須檢查串流已結束。 / A stream that exactly fills the budget must still end cleanly.
    with refused('unaccounted gzip bytes'):
        add(tmp_path, gzip.compress(b'x' * 16, mtime=0) + b'trailing', limits=small)


# 成員名稱、深度與數量 / Member names, depth and count

@pytest.mark.parametrize('name', ['', '/etc/passwd', '../escape.txt', 'a/../../b', 'dir\\file', 'nul\x00name'],
                         ids=['empty', 'absolute', 'parent', 'nested-parent', 'backslash', 'nul'])
def test_unsafe_member_names_are_refused(tmp_path, name):
    with refused('unsafe archive member name'):
        ContentInventory(tmp_path).member(name)


def test_member_count_boundary(tmp_path):
    inventory = ContentInventory(tmp_path, limits=replace(LIMITS, max_members=2))
    inventory.member('a.txt')
    inventory.member('b.txt')
    assert inventory.members == 2
    with limited('archive member limit exceeded'):
        inventory.member('c.txt')


def test_archive_depth_boundary(tmp_path):
    data = b'synthetic'
    for _ in range(3):
        data = gzip.compress(data, mtime=0)
    assert add(tmp_path, data).archives == 3
    with limited('archive recursion depth exceeded'):
        add(tmp_path, gzip.compress(data, mtime=0))


def test_expanded_byte_accounting_boundary(tmp_path):
    inventory = ContentInventory(tmp_path)
    assert inventory.account(b'abcd', 4) == b'abcd'
    assert inventory.expanded_bytes == 4
    with limited('expanded content byte limit exceeded'):
        inventory.account(b'abcde', 4)
    assert inventory.expanded_bytes == 4


# 二進位內容 / Binary content

def binary():
    return b'\x89PNG\r\n\x1a\n' + bytes(range(32)) + b' embedded plaintext '


def test_unreviewed_binary_is_refused_and_reviewed_binary_is_scanned_as_strings(tmp_path):
    with refused('binary content needs an adapter or a reviewed digest in the binary allowlist'):
        add(tmp_path, binary())
    inventory = add(tmp_path, binary(), reviewed_binaries=frozenset({hashlib.sha256(binary()).hexdigest()}))
    assert files(inventory) == ['bundle.bin!strings'] and inventory.reviewed == 1


def test_text_is_a_single_leaf_without_review(tmp_path):
    inventory = add(tmp_path, b'plain text\n')
    assert files(inventory) == ['bundle.bin'] and inventory.reviewed == 0 and inventory.archives == 0
