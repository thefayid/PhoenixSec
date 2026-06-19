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


def test_advanced_taint_propagation(tmp_path):
    db_file = tmp_path / "db_helper.py"
    db_file.write_text(
        "def execute_query(query_str):\n"
        "    cursor.execute('SELECT * FROM users WHERE username = ' + query_str)\n"
        "    return query_str\n",
        encoding="utf-8"
    )

    middleware_file = tmp_path / "middleware.py"
    middleware_file.write_text(
        "from db_helper import execute_query\n"
        "def run_sql(sql_input):\n"
        "    execute_query(sql_input)\n"
        "    return sql_input\n",
        encoding="utf-8"
    )

    app_file = tmp_path / "app.py"
    app_code = (
        "from middleware import run_sql\n"
        "def controller(request):\n"
        "    user_input = request.GET['username']\n"
        "    query_var = 'PREFIX_' + user_input\n"
        "    run_sql(query_var)\n"
    )
    app_file.write_text(app_code, encoding="utf-8")

    analyzer = TaintAnalyzer()
    analyzer.analyze_directory(tmp_path)

    assert "run_sql" in analyzer.functions
    assert 0 in analyzer.functions["run_sql"].sink_params

    findings = analyzer.trace_file_calls(app_file, app_code)
    assert len(findings) == 1
    assert findings[0].vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert findings[0].line_number == 5
    assert findings[0].source == "request.GET['username']"


def test_cross_file_command_injection_and_path_traversal(tmp_path):
    # 1. Create a helper with command injection and path traversal sinks
    helper_file = tmp_path / "helpers.py"
    helper_file.write_text(
        "import subprocess\n"
        "def run_cmd(command):\n"
        "    subprocess.run(command, shell=True)\n"
        "def read_file(path):\n"
        "    open(path + '.txt')\n",
        encoding="utf-8"
    )

    # 2. Create app file
    app_file = tmp_path / "app.py"
    app_code = (
        "from helpers import run_cmd, read_file\n"
        "def test(request):\n"
        "    val = request.GET['val']\n"
        "    run_cmd(val)\n"
        "    read_file(val)\n"
    )
    app_file.write_text(app_code, encoding="utf-8")

    analyzer = TaintAnalyzer()
    analyzer.analyze_directory(tmp_path)

    # Verify functions are registered with their correct sink parameter indices
    assert "run_cmd" in analyzer.functions
    assert "read_file" in analyzer.functions
    assert 0 in analyzer.functions["run_cmd"].sink_params
    assert 0 in analyzer.functions["read_file"].sink_params

    # Run trace and assert correct vulnerability types and CWEs are generated
    findings = analyzer.trace_file_calls(app_file, app_code)
    assert len(findings) == 2

    # Check Command Injection finding
    cmd_findings = [f for f in findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
    assert len(cmd_findings) == 1
    assert cmd_findings[0].cwe_id == "CWE-78"

    # Check Path Traversal finding
    pt_findings = [f for f in findings if f.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL]
    assert len(pt_findings) == 1
    assert pt_findings[0].cwe_id == "CWE-22"


def test_taint_complex_calls(tmp_path):
    # Verifies multi-line call, nested call, and lambda/closure parameter arguments
    helper_file = tmp_path / "helper.py"
    helper_file.write_text(
        "def do_query(q):\n"
        "    cursor.execute(f'SELECT * FROM u WHERE id = {q}')\n",
        encoding="utf-8"
    )

    app_file = tmp_path / "app.py"
    app_code = (
        "from helper import do_query\n"
        "def handle(request):\n"
        "    # Multi-line call:\n"
        "    do_query(\n"
        "        request.GET['id']\n"
        "    )\n"
        "    # Nested call:\n"
        "    do_query(str(request.GET['id']))\n"
        "    # Call with lambda/closure arg:\n"
        "    do_query((lambda: request.GET['id'])())\n"
    )
    app_file.write_text(app_code, encoding="utf-8")

    analyzer = TaintAnalyzer()
    analyzer.analyze_directory(tmp_path)

    findings = analyzer.trace_file_calls(app_file, app_code)
    # Under AST analysis, all 3 calls should be successfully traced!
    assert len(findings) == 3
    for f in findings:
        assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION


def test_circular_call_graph_termination(tmp_path):
    # Verifies that circular dependencies do not infinite-loop
    f1 = tmp_path / "f1.py"
    f1.write_text(
        "from f2 import func2\n"
        "def func1(a):\n"
        "    func2(a)\n",
        encoding="utf-8"
    )

    f2 = tmp_path / "f2.py"
    f2.write_text(
        "from f1 import func1\n"
        "def func2(b):\n"
        "    func1(b)\n",
        encoding="utf-8"
    )

    analyzer = TaintAnalyzer()
    # If circular call graph is circular, analyze_directory must terminate successfully!
    analyzer.analyze_directory(tmp_path)

    assert "func1" in analyzer.functions
    assert "func2" in analyzer.functions


