from typer.testing import CliRunner
from opensurity.cli.main import app

runner = CliRunner()

def test_3agent_demo():
    result = runner.invoke(app, ["demo", "--agents", "3"])
    assert result.exit_code == 0
    assert "Starting OpenSurity Demo Pipeline" in result.stdout
    assert "Pipeline Complete!" in result.stdout
    assert "--- Trust Log Summary ---" in result.stdout
