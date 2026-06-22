import time
from typer.testing import CliRunner
from opensurity.cli.main import app

runner = CliRunner()

def test_demo_timing():
    start_time = time.perf_counter()
    result = runner.invoke(app, ["demo", "--agents", "3"])
    end_time = time.perf_counter()
    
    elapsed_time = end_time - start_time
    assert result.exit_code == 0
    assert elapsed_time < 120.0, f"Demo took {elapsed_time}s, longer than 120s limit"
