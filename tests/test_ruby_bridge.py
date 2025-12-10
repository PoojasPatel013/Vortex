import pytest
import os
import json
from unittest.mock import MagicMock, patch
from netra.core.modules.ruby_bridge import RubyBridge

# Mock data
MOCK_RUBY_OUTPUT = json.dumps({
  "target": "example.com",
  "message": "Hello from Ruby",
  "vulnerabilities": [
      {
        "type": "Test Vuln",
        "severity": "Info"
      }
  ]
})

@pytest.fixture
def mock_subprocess():
    with patch("subprocess.run") as mock_run:
        yield mock_run

@pytest.fixture
def bridge():
    return RubyBridge()

@pytest.mark.asyncio
async def test_list_scripts(bridge):
    # Mock os.listdir and os.path.exists
    with patch("os.path.exists", return_value=True):
        with patch("os.listdir", return_value=["test.rb", "iam_scan.rb", "resilience_scan.rb", "threat_scan.rb"]):
            scripts = bridge.list_scripts()
            assert "test.rb" in scripts
            assert "iam_scan.rb" in scripts
            assert "threat_scan.rb" in scripts

@pytest.mark.asyncio
async def test_execute_script_success(bridge, mock_subprocess):
    # Setup mock
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = MOCK_RUBY_OUTPUT
    mock_result.stderr = ""
    mock_subprocess.return_value = mock_result
    
    target = "example.com"
    
    # Execute
    # We must patch exists because the bridge checks for file presence
    with patch("os.path.exists", return_value=True):
        result = bridge.execute_script("test.rb", target)
    
    # Verify
    assert "error" not in result
    assert result["target"] == target
    assert result["vulnerabilities"][0]["type"] == "Test Vuln"
    
    # Verify subprocess called correctly
    expected_path = os.path.join(bridge.scripts_dir, "test.rb")
    mock_subprocess.assert_called_with(["ruby", expected_path, target], capture_output=True, text=True, timeout=30)

@pytest.mark.asyncio
async def test_execute_script_json_error(bridge, mock_subprocess):
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Invalid JSON Output from Ruby"
    mock_subprocess.return_value = mock_result
    
    with patch("os.path.exists", return_value=True):
         result = bridge.execute_script("test.rb", "foo")
    
    assert "error" in result
    assert result["error"] == "Invalid JSON output"

@pytest.mark.asyncio
async def test_execute_script_process_fail(bridge, mock_subprocess):
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "Ruby Syntax Error"
    mock_subprocess.return_value = mock_result
    
    with patch("os.path.exists", return_value=True):
        result = bridge.execute_script("test.rb", "foo")
    
    assert "error" in result
    assert "Execution failed" in result["error"]
