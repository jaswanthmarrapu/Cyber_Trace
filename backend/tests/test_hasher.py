import io
from app.forensic.hasher import calculate_stream_hashes

def test_stream_hasher_sha256():
    test_bytes = b"CyberTrace Forensic Test Data 2026"
    stream = io.BytesIO(test_bytes)
    result = calculate_stream_hashes(stream)

    assert "sha256" in result
    assert "sha1" in result
    assert "md5" in result
    assert len(result["sha256"]) == 64
    assert len(result["sha1"]) == 40
    assert len(result["md5"]) == 32

