from detector import flag_suspicious_ips


# Test 1: IP appears exactly 5 times (meets threshold)
def test_ip_exactly_5_times():
    ips = ["192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.1", "192.168.1.1"]
    result = flag_suspicious_ips(ips)
    assert "192.168.1.1" in result


# Test 2: IP appears 6 times (exceeds threshold)
def test_ip_more_than_5_times():
    ips = ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1"]
    result = flag_suspicious_ips(ips)
    assert "10.0.0.1" in result


# Test 3: IP appears 4 times (below threshold)
def test_ip_less_than_5_times():
    ips = ["172.16.0.1", "172.16.0.1", "172.16.0.1", "172.16.0.1"]
    result = flag_suspicious_ips(ips)
    assert "172.16.0.1" not in result


# Test 4: Two IPs, one above and one below threshold
def test_mixed_ips():
    ips = ["1.1.1.1", "1.1.1.1", "1.1.1.1", "1.1.1.1", "1.1.1.1", "2.2.2.2", "2.2.2.2"]
    result = flag_suspicious_ips(ips)
    assert "1.1.1.1" in result
    assert "2.2.2.2" not in result


# Test 5: Empty list (no IPs)
def test_empty_list():
    ips = []
    result = flag_suspicious_ips(ips)
    assert result == {}
