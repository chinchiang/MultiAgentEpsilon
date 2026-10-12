"""有限額地展開封存為平面檔案，不把封存路徑直接解到磁碟。

Bounded archive expansion into flat files; never extract archive paths to disk."""
import hashlib
import io
import json
import re
import tarfile
import zipfile
import zlib
from pathlib import PurePosixPath

from .limits import LIMITS, ResourceLimit

MIN_STRING = 6
ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STRING)
UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_STRING)
GZIP_TEXT = re.compile(rb"[\x20-\x7e]*")
# ZIP64、NTFS 時間、延伸時間戳記與 Unix UID/GID 的資料長度上限。 / Data-length caps for ZIP64, NTFS times,
# extended timestamps and Unix UID/GID records.
ZIP_EXTRA_LIMITS = {0x0001: 28, 0x000a: 32, 0x5455: 13, 0x7875: 19}


class UnsupportedContent(ValueError):
    pass


def load_binary_allowlist(path):
    """以內容摘要核准二進位資料，不以路徑核准；同內容歷史副本可沿用審查，內容變更須重新審查。

Trusted, digest-keyed review of binary blobs. Keyed by content, not path, so one
    reviewed asset also covers its historical copies; a changed binary needs review again."""
    if not path.exists():
        return frozenset()
    data = json.loads(path.read_text())
    entries = data.get("entries") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1
            or not isinstance(entries, list) or
            any(not isinstance(e, dict) or set(e) != {"sha256", "reason"} or
                not re.fullmatch(r"[0-9a-f]{64}", str(e["sha256"])) or
                not isinstance(e["reason"], str) or not e["reason"].strip() for e in entries) or
            len({e["sha256"] for e in entries}) != len(entries)):
        raise ValueError("invalid binary allowlist")
    return frozenset(e["sha256"] for e in entries)


def is_text(data):
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError:
        return False
    return not any(ord(char) < 32 and char not in '\n\r\t' for char in text)


def printable_strings(data):
    """擷取 ASCII 與 UTF-16LE 內嵌明文，等同 strings 的相應字串視圖。

Embedded plaintext (ASCII and UTF-16LE, as `strings -e s/l` would see it)."""
    runs = [m.group() for m in ASCII_RUN.finditer(data)]
    runs += [m.group().decode("utf-16-le").encode() for m in UTF16LE_RUN.finditer(data)]
    return b"\n".join(runs) + b"\n"


def number(data, start, size):
    return int.from_bytes(data[start:start+size], 'little')


def zip_extra(field):
    """extra 欄位只接受已知格式且有長度上限的紀錄，不能夾帶任意壓縮內容。

Extra fields may only hold known, length-capped records, never arbitrary compressed data."""
    position = 0
    while position < len(field):
        if len(field) - position < 4:
            raise UnsupportedContent("unsupported zip extra field")
        tag, size = number(field, position, 2), number(field, position + 2, 2)
        position += 4
        if size > ZIP_EXTRA_LIMITS.get(tag, -1) or position + size > len(field):
            raise UnsupportedContent("unsupported zip extra field")
        position += size


def zip_central(data, archive):
    """中央目錄、ZIP64 結尾紀錄與結尾紀錄須逐位元組對應，註解須為文字，且結尾紀錄後不得有資料。

The central directory, ZIP64 end records and end record must account for every
    remaining byte; comments must be text and nothing may follow the end record."""
    position = archive.start_dir
    for _ in archive.infolist():
        if data[position:position+4] != b'PK\x01\x02':
            raise UnsupportedContent("unaccounted zip bytes")
        names, extra, comment = (number(data, position + offset, 2) for offset in (28, 30, 32))
        position += 46 + names
        zip_extra(data[position:position+extra])
        position += extra
        if not is_text(data[position:position+comment]):
            raise UnsupportedContent("binary zip comment")
        position += comment
    if data[position:position+4] == b'PK\x06\x06':
        # ZIP64 結尾紀錄不接受可延伸資料區。 / The ZIP64 end record may not carry an extensible data sector.
        if number(data, position + 4, 8) != 44 or data[position+56:position+60] != b'PK\x06\x07':
            raise UnsupportedContent("unaccounted zip bytes")
        position += 76
    if data[position:position+4] != b'PK\x05\x06' or position + 22 + number(data, position + 20, 2) != len(data):
        raise UnsupportedContent("unaccounted zip bytes")
    if not is_text(data[position+22:]):
        raise UnsupportedContent("binary zip comment")


def zip_payloads(data, archive):
    """列出成員的 payload 範圍；成員以外的每一位元組都須屬於已知結構，避免藏入未列出壓縮內容。

Payload ranges of the listed members. Every other byte must belong to a known
    structure, so no compressed payload can hide between, before or after entries."""
    position = 0
    payloads = []
    for member in sorted(archive.infolist(), key=lambda m: m.header_offset):
        if member.header_offset != position or data[position:position+4] != b'PK\x03\x04':
            raise UnsupportedContent("unaccounted zip bytes")
        names = number(data, position + 26, 2)
        extra = number(data, position + 28, 2)
        zip_extra(data[position+30+names:position+30+names+extra])
        position += 30 + names + extra
        payloads.append((position, member.compress_size))
        position += member.compress_size
        if member.flag_bits & 0x08:
            sizes = (16, 24) if data[position:position+4] == b'PK\x07\x08' else (12, 20)
            following = [m.header_offset for m in archive.infolist() if m.header_offset > member.header_offset]
            target = min(following, default=archive.start_dir)
            if target - position not in sizes:
                raise UnsupportedContent("unaccounted zip bytes")
            position = target
    if position != archive.start_dir:
        raise UnsupportedContent("unaccounted zip bytes")
    zip_central(data, archive)
    return payloads


def outside(data, payloads):
    """將已另行掃描的成員 payload 遮空，留下容器本身位元組。

Container bytes with member payloads (scanned as their own leaves) blanked."""
    masked = bytearray(data)
    for start, size in payloads:
        masked[start:start+size] = bytes(size)
    return bytes(masked)


class ContentInventory:
    def __init__(self, directory, limits=LIMITS, reviewed_binaries=frozenset()):
        self.directory = directory
        self.limits = limits
        self.reviewed_binaries = reviewed_binaries
        self.entries = {}
        self.expanded_bytes = 0
        self.members = 0
        self.archives = 0
        self.reviewed = 0

    def budget(self):
        return min(self.limits.max_file_bytes, self.limits.max_expanded_bytes - self.expanded_bytes)

    def account(self, value, maximum):
        if len(value) > maximum:
            raise ResourceLimit("expanded content byte limit exceeded")
        self.expanded_bytes += len(value)
        return value

    def read(self, stream):
        maximum = self.budget()
        return self.account(stream.read(maximum + 1), maximum)

    def gunzip(self, data):
        """只接受單一 gzip 成員：標頭不得有 extra 欄位，檔名與註解須為可讀 ASCII，結尾後只允許零填補。

A single gzip member only: no header extra field, printable-ASCII name and
        comment, and nothing but zero padding after the trailer."""
        flags = data[3] if len(data) > 3 else 0
        if len(data) < 18 or data[2] != 8 or flags & 0xe4:
            raise UnsupportedContent("unsupported gzip header")
        position = 10
        for flag in (0x08, 0x10):
            if flags & flag:
                end = data.find(b'\x00', position)
                if end < 0 or not GZIP_TEXT.fullmatch(data[position:end]):
                    raise UnsupportedContent("binary gzip header field")
                position = end + 1
        maximum = self.budget()
        stream = zlib.decompressobj(31)
        try:
            value = stream.decompress(data, maximum + 1)
        except zlib.error:
            raise UnsupportedContent("corrupt gzip stream") from None
        if len(value) <= maximum and (not stream.eof or stream.unused_data.strip(b'\x00')):
            raise UnsupportedContent("unaccounted gzip bytes")
        return self.account(value, maximum)

    def member(self, name):
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name or '\x00' in name:
            raise UnsupportedContent("unsafe archive member name")
        self.members += 1
        if self.members > self.limits.max_members:
            raise ResourceLimit("archive member limit exceeded")

    def add(self, data, origin, *, scope, depth=0, object_id=None):
        # 依 magic 判定格式，不信任副檔名或掃描器隱含排除。 / Magic detection does not trust extensions or the scanner's implicit exclusions.
        is_gzip = data.startswith(b'\x1f\x8b')
        is_zip = data.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'))
        is_tar = len(data) >= 512 and data[257:262] == b'ustar'
        if is_gzip or is_zip or is_tar:
            if depth >= self.limits.max_archive_depth:
                raise ResourceLimit("archive recursion depth exceeded")
            self.archives += 1
        payloads = []
        if is_gzip:
            self.member('gzip-stream')
            self.add(self.gunzip(data), origin + '!gzip', scope=scope, depth=depth+1, object_id=object_id)
        elif is_zip:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                payloads = zip_payloads(data, archive)
                for member in archive.infolist():
                    self.member(member.filename)
                    if member.flag_bits & 1 or (member.external_attr >> 16) & 0o170000 == 0o120000:
                        raise UnsupportedContent("encrypted or symlink archive member")
                    if member.is_dir():
                        if member.file_size or member.compress_size > 2:
                            raise UnsupportedContent("directory archive member carries data")
                        continue
                    if member.file_size > self.limits.max_file_bytes:
                        raise ResourceLimit("archive member too large")
                    with archive.open(member) as stream:
                        self.add(self.read(stream), origin + '!' + member.filename,
                                 scope=scope, depth=depth+1, object_id=object_id)
        elif is_tar:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
                for member in archive:
                    self.member(member.name)
                    payloads.append((member.offset_data, member.size))
                    if member.isdir():
                        if member.size:
                            raise UnsupportedContent("directory archive member carries data")
                        continue
                    if not member.isfile():
                        raise UnsupportedContent("non-regular tar member")
                    if member.size > self.limits.max_file_bytes:
                        raise ResourceLimit("tar member too large")
                    with archive.extractfile(member) as stream:
                        self.add(self.read(stream), origin + '!' + member.name,
                                 scope=scope, depth=depth+1, object_id=object_id)
                # 最後成員後的位元組（含結尾填補）必須全為零。 / Bytes after the last member (end-of-archive padding included) must be zero.
                if data[archive.offset:].strip(b'\x00'):
                    raise UnsupportedContent("data after tar end-of-archive")
        if is_gzip or is_zip or is_tar:
            # 標頭、名稱、註解與 extra 欄位不屬於成員 payload。 / Headers, names, comments and extra fields are not member payloads.
            self.leaf(printable_strings(outside(data, payloads)), origin + '!container-strings', scope, object_id)
        else:
            if not is_text(data):
                if hashlib.sha256(data).hexdigest() not in self.reviewed_binaries:
                    raise UnsupportedContent("binary content needs an adapter or a reviewed digest in the binary allowlist")
                # 已審查資產仍須掃描內嵌明文機密。 / A reviewed asset is still scanned for embedded plaintext secrets.
                self.reviewed += 1
                data, origin = printable_strings(data), origin + '!strings'
            self.leaf(data, origin, scope, object_id)

    def leaf(self, data, origin, scope, object_id):
        if len(self.entries) >= self.limits.max_files:
            raise ResourceLimit("scan leaf count exceeded")
        name = f'input-{len(self.entries):06d}.txt'
        (self.directory / name).write_bytes(data)
        self.entries[name] = {'file': origin, 'scope': scope, 'bytes': len(data), 'object_id': object_id}
