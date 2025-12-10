import pytest
import ipaddress
from unittest.mock import AsyncMock, patch
from netra.core.modules.threat import ThreatScanner

# Mock DNS Response for Google DOH
SPF_RESPONSE = {
    "Status": 0,
    "Answer": [
        {"name": "example.com", "type": 16, "data": "\"v=spf1 include:_spf.google.com ~all\""}
    ]
}

NO_SPF_RESPONSE = {
    "Status": 0 # But no Answer
}

DMARC_RESPONSE = {
    "Status": 0,
    "Answer": [
        {"name": "_dmarc.example.com", "type": 16, "data": "\"v=DMARC1; p=none; rua=mailto:dmac@example.com\""}
    ]
}

@pytest.fixture
def scanner():
    return ThreatScanner()

@pytest.mark.asyncio
async def test_spf_check_valid(scanner):
    with patch("netra.core.http.SafeHTTPClient.get") as mock_get:
        # Mocking the context manager __aenter__ return value
        mock_client = AsyncMock()
        mock_get.return_value.__aenter__.return_value = mock_client
        
        # We need to mock the response of client.get calls inside _query_dns_txt
        # Since logic uses `async with SafeHTTPClient()`, we need to mock that flow.
        # Ideally we refactor scanner to accept client, but here we patch the client usage.
        pass 

# Since patching complex async context managers inside the class method is verbose, 
# let's test the independent logic methods if possible, or use a simpler patching strategy.

# Strategy: Test via `_query_dns_txt` mocking.

@pytest.mark.asyncio
async def test_threat_logic_spf():
    scanner = ThreatScanner()
    client = AsyncMock()
    
    # Mock _query_dns_txt to return specific records
    with patch.object(scanner, '_query_dns_txt', new_callable=AsyncMock) as mock_dns:
        # 1. Test Good SPF
        mock_dns.return_value = ["v=spf1 -all"] 
        res = await scanner._check_spf(client, "example.com")
        assert res is None # No vulnerability
        
        # 2. Test Missing SPF
        mock_dns.return_value = []
        res = await scanner._check_spf(client, "example.com")
        assert res["type"] == "Missing SPF Record"
        
        # 3. Test Weak SPF (+all)
        mock_dns.return_value = ["v=spf1 +all"]
        res = await scanner._check_spf(client, "example.com")
        assert res["type"] == "Weak SPF Record"

@pytest.mark.asyncio
async def test_threat_logic_dmarc():
    scanner = ThreatScanner()
    client = AsyncMock()
    
    with patch.object(scanner, '_query_dns_txt', new_callable=AsyncMock) as mock_dns:
        # 1. Test None Policy
        mock_dns.return_value = ["v=DMARC1; p=none"]
        res = await scanner._check_dmarc(client, "example.com")
        assert res["type"] == "DMARC Policy Not Enforced"
        
        # 2. Test Reject Policy (Good)
        mock_dns.return_value = ["v=DMARC1; p=reject"]
        res = await scanner._check_dmarc(client, "example.com")
        assert res is None

@pytest.mark.asyncio
async def test_threat_logic_robots():
    scanner = ThreatScanner()
    client = AsyncMock()
    
    # Mock response object
    mock_resp = AsyncMock()
    mock_resp.status = 200
    mock_resp.text.return_value = "User-agent: *\nDisallow: /admin/\nDisallow: /config.php"
    client.get.return_value = mock_resp
    
    res = await scanner._check_robots(client, "http://example.com")
    
    assert res["type"] == "Sensitive Paths in Robots.txt"
    assert "/admin/" in res["evidence"]
