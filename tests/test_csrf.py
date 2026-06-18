from __future__ import annotations

from phoenixsec.rules.csrf import PythonCSRFRule


def test_python_csrf_disabled() -> None:
    code = """
from flask import Flask
app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
    """
    rule = PythonCSRFRule()
    finding = rule.scan(code, "app.py")
    assert finding is not None
    assert finding.vulnerability_type == "Cross-Site Request Forgery (CSRF)"


def test_python_csrf_django_exempt() -> None:
    code = """
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def my_view(request):
    pass
    """
    rule = PythonCSRFRule()
    finding = rule.scan(code, "views.py")
    assert finding is not None


def test_python_csrf_safe() -> None:
    code = """
from flask import Flask
app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = True
    """
    rule = PythonCSRFRule()
    finding = rule.scan(code, "app.py")
    assert finding is None
