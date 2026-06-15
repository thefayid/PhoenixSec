from phoenixsec.core.taint_analyzer import TaintAnalyzer
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_cross_file_taint_propagation(tmp_path):
    # 1. Create a helper module with a function definition that contains a sink
    helper_file = tmp_path / "db_helper.py"
    helper_file.write_text(
        "def execute_query(query_str):\n"
        "    # Dangerous sink execution\n"
        "    cursor.execute('SELECT * FROM users WHERE username = ' + query_str)\n"
        "    return query_str\n",
        encoding="utf-8",
    )

    # 2. Create an app module that takes user input and calls the helper function
    app_file = tmp_path / "app.py"
    app_code = (
        "def controller(request):\n"
        "    user_input = request.GET['username']\n"
        "    execute_query(user_input)\n"
    )
    app_file.write_text(app_code, encoding="utf-8")

    # 3. Instantiate and run TaintAnalyzer
    analyzer = TaintAnalyzer()
    analyzer.analyze_directory(tmp_path)

    # Check that execute_query was registered
    assert "execute_query" in analyzer.functions
    func_def = analyzer.functions["execute_query"]
    assert func_def.params == ["query_str"]
    assert 0 in func_def.sink_params  # index 0 (query_str) should be marked as sink
    assert 0 in func_def.return_params  # index 0 should be marked as return parameter

    # Trace calls in app.py
    findings = analyzer.trace_file_calls(app_file, app_code)
    assert len(findings) == 1

    finding = findings[0]
    assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert finding.severity == Severity.CRITICAL
    assert finding.line_number == 3
    assert finding.source == "request.GET['username']"
    assert "execute_query" in finding.sink
