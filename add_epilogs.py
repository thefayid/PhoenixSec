from werkzeug.utils import secure_filename
import pathlib

file_path = pathlib.Path(secure_filename(r"e:\Phoenix Sec\src\phoenixsec\cli\main.py"))
content = file_path.read_text(encoding="utf-8")

epilogs = {
    "def version(": 'epilog="Examples:\\n  phoenixsec version"',
    "def scan(": 'epilog="Examples:\\n  phoenixsec scan ./src --severity HIGH --format json\\n  phoenixsec scan ./src --patch"',
    "def report(": 'epilog="Examples:\\n  phoenixsec report ./reports/result.json --format html"',
    "def install_hook(": 'epilog="Examples:\\n  phoenixsec install-hook . --severity HIGH"',
    "def webhook(": 'epilog="Examples:\\n  phoenixsec webhook --port 8080 --secret mysecret --fail-on HIGH"',
    "def api(": 'epilog="Examples:\\n  phoenixsec api --host 127.0.0.1 --port 8000"',
    "def benchmark(": 'epilog="Examples:\\n  phoenixsec benchmark --dir benchmarks"',
    "def scan_org(": 'epilog="Examples:\\n  phoenixsec scan-org my-org --format json\\n  phoenixsec scan-org my-org --workers 8 --no-sca"',
    "def init(": 'epilog="Examples:\\n  phoenixsec init\\n  phoenixsec init --non-interactive"',
    "def watch(": 'epilog="Examples:\\n  phoenixsec watch ./src --severity HIGH --interval 2.0"',
    "def lsp(": 'epilog="Examples:\\n  phoenixsec lsp"',
}

lines = content.splitlines()
for i, line in enumerate(lines):
    if line.startswith("@app.command("):
        # find the associated def
        for j in range(i + 1, min(i + 10, len(lines))):
            if lines[j].startswith("def "):
                for key, epilog in epilogs.items():
                    if lines[j].startswith(key):
                        # Modify the @app.command(...) line
                        if line == "@app.command()":
                            lines[i] = f"@app.command({epilog})"
                        else:
                            # It's something like @app.command(name="api")
                            lines[i] = line[:-1] + f", {epilog})"
                break

file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("Successfully added epilogs.")
