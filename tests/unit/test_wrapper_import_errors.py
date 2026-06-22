import sys
import pytest

def test_langgraph_import_error():
    if "langgraph" in sys.modules:
        del sys.modules["langgraph"]
    if "opensurity.wrappers.langgraph" in sys.modules:
        del sys.modules["opensurity.wrappers.langgraph"]
        
    with pytest.raises(ImportError, match=r"opensurity\[langgraph\] extra required"):
        import opensurity.wrappers.langgraph  # noqa: F401

def test_crewai_import_error():
    if "crewai" in sys.modules:
        del sys.modules["crewai"]
    if "opensurity.wrappers.crewai" in sys.modules:
        del sys.modules["opensurity.wrappers.crewai"]
        
    with pytest.raises(ImportError, match=r"opensurity\[crewai\] extra required"):
        import opensurity.wrappers.crewai  # noqa: F401

def test_autogen_import_error():
    if "autogen" in sys.modules:
        del sys.modules["autogen"]
    if "opensurity.wrappers.autogen" in sys.modules:
        del sys.modules["opensurity.wrappers.autogen"]
        
    with pytest.raises(ImportError, match=r"opensurity\[autogen\] extra required"):
        import opensurity.wrappers.autogen  # noqa: F401
