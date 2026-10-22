import subprocess

def test_cli_help():
    """Test that the application's help menu prints successfully."""
    # Runs: python securepad.py --help
    result = subprocess.run(
        ["python", "securepad.py", "--help"], 
        capture_output=True, 
        text=True
    )
    
    # Assert that the program exited with code 0 (success)
    assert result.returncode == 0
    # Make sure something about encryption or help is in the output
    assert "encrypt" in result.stdout or "help" in result.stdout.lower()

def test_cli_version():
    """Test that the application version command works."""
    # Runs: python securepad.py --version
    result = subprocess.run(
        ["python", "securepad.py", "--version"], 
        capture_output=True, 
        text=True
    )
    assert result.returncode == 0

