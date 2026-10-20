"""Read-only GPT host-header verifier tests; synthetic bytes, NO real disk writes."""
from __future__ import annotations
import struct,unittest,uuid,zlib
from scripts.windows_w1_gpt_header import verify_gpt_primary,GPTIdentityRefused

GUID="52aa5640-1a2d-4624-a3b2-67c2fa84ce92"
CAPACITY=64*1024**3

def sample(guid=GUID,capacity=CAPACITY):
    mbr=bytearray(512)
    mbr[450]=0xee
    mbr[510:512]=bytes.fromhex("55aa")
    entries=bytes(128*128)
    hdr=bytearray(512)
    hdr[:8]=b"EFI PART"
    struct.pack_into("<IIII",hdr,8,0x10000,92,0,0)
    struct.pack_into("<QQQQ",hdr,24,1,capacity//512-1,34,capacity//512-34)
    hdr[56:72]=uuid.UUID(guid).bytes_le
    struct.pack_into("<QIII",hdr,72,2,128,128,zlib.crc32(entries)&0xffffffff)
    struct.pack_into("<I",hdr,16,zlib.crc32(hdr[:92])&0xffffffff)
    return bytes(mbr)+bytes(hdr)+entries

def changed(data,offset,new):
    x=bytearray(data);x[offset:offset+len(new)]=new;return bytes(x)

class HostGPTEvidence(unittest.TestCase):
    def test_verifies_primary_header_and_empty_table(self):
        x=verify_gpt_primary(sample(),expected_guid=GUID,virtual_size_bytes=CAPACITY)
        self.assertEqual(x["disk_guid"],GUID)
        self.assertEqual(x["virtual_size_bytes"],CAPACITY)
        self.assertTrue(x["primary_header_crc_valid"])
        self.assertTrue(x["empty_partition_table_crc_valid"])
        self.assertFalse(x["destructive_windows_setup_authorized"])
        self.assertFalse(x["actual_winpe_observed"])

    def test_corruption_or_missing_protective_mbr_refused(self):
        for name,x in (
            ("mbr_sig",changed(sample(),510,b"\0\0")),
            ("mbr_type",changed(sample(),450,b"\0")),
            ("primary_signature",changed(sample(),512,b"BAD GPT!")),
            ("header_crc",changed(sample(),512+16,b"\0\0\0\0")),
            ("partition_table_crc",changed(sample(),1024,b"\x13")),
            ("header_guid",changed(sample(),512+56,uuid.uuid4().bytes_le)),
            ("truncated",sample()[:1024]),
        ):
            with self.subTest(name=name),self.assertRaises(GPTIdentityRefused):
                verify_gpt_primary(x,expected_guid=GUID,virtual_size_bytes=CAPACITY)

    def test_wrong_capacity_guid_or_partition_layout_refused(self):
        with self.assertRaises(GPTIdentityRefused):
            verify_gpt_primary(sample(),expected_guid=str(uuid.uuid4()),virtual_size_bytes=CAPACITY)
        with self.assertRaises(GPTIdentityRefused):
            verify_gpt_primary(sample(),expected_guid=GUID,virtual_size_bytes=CAPACITY//2)
        with self.assertRaises(GPTIdentityRefused):
            verify_gpt_primary(sample(),expected_guid=GUID,virtual_size_bytes=True)
        with self.assertRaises(GPTIdentityRefused):
            verify_gpt_primary(sample(),expected_guid="not-a-uuid",virtual_size_bytes=CAPACITY)

    def test_only_empty_gpt_admitted_even_with_valid_partition_crc(self):
        d=bytearray(sample())
        entries=bytearray(128*128);entries[0]=0x33
        d[1024:1024+len(entries)]=entries
        hdr=bytearray(d[512:1024])
        struct.pack_into("<I",hdr,88,zlib.crc32(entries)&0xffffffff)
        struct.pack_into("<I",hdr,16,0)
        struct.pack_into("<I",hdr,16,zlib.crc32(hdr[:92])&0xffffffff)
        d[512:1024]=hdr
        with self.assertRaises(GPTIdentityRefused):
            verify_gpt_primary(bytes(d),expected_guid=GUID,virtual_size_bytes=CAPACITY)

if __name__=="__main__":
    unittest.main()
