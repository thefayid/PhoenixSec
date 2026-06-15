from __future__ import annotations

import phoenixsec.rules.insecure_deserialization  # noqa: F401
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.rules.base_rule import RuleContext
from phoenixsec.rules.insecure_deserialization import (
    JavaInsecureDeserializationRule,
    JavaScriptInsecureDeserializationRule,
    PythonInsecureDeserializationRule,
)


def test_python_deserialization_detection() -> None:
    code = """
import pickle
def load_data(request):
    data = request.body
    obj = pickle.loads(data)
    return obj
"""
    rule = PythonInsecureDeserializationRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION
    assert "pickle.loads" in findings[0].sink


def test_python_deserialization_safe() -> None:
    code = """
import json
def load_data(request):
    data = request.body
    obj = json.loads(data)
    return obj
"""
    rule = PythonInsecureDeserializationRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.py", "python"))
    assert len(findings) == 0


def test_js_deserialization_detection() -> None:
    code = """
const serialize = require('node-serialize');
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    const obj = serialize.unserialize(data);
    res.send(obj);
});
"""
    rule = JavaScriptInsecureDeserializationRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION
    assert "serialize" in findings[0].sink


def test_js_deserialization_safe() -> None:
    code = """
app.post('/deserialize', (req, res) => {
    const data = req.body.data;
    const obj = JSON.parse(data);
    res.send(obj);
});
"""
    rule = JavaScriptInsecureDeserializationRule()
    findings = rule.scan_context(RuleContext.from_code(code, "test.js", "javascript"))
    assert len(findings) == 0


def test_java_deserialization_detection() -> None:
    code = """
public Object deserialize(byte[] data) throws Exception {
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);
    return ois.readObject();
}
"""
    rule = JavaInsecureDeserializationRule()
    findings = rule.scan_context(RuleContext.from_code(code, "Test.java", "java"))
    assert len(findings) >= 1
    assert findings[0].vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION
    assert "ObjectInputStream" in findings[0].sink
