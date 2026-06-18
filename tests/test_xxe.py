from __future__ import annotations

from phoenixsec.rules.xxe import JavaXXERule, PythonXXERule


def test_python_xxe_lxml() -> None:
    code = """
import lxml.etree
parser = lxml.etree.XMLParser()
tree = lxml.etree.parse("data.xml", parser)
    """
    rule = PythonXXERule()
    finding = rule.scan(code, "app.py")
    assert finding is not None
    assert finding.vulnerability_type == "XML External Entity (XXE)"


def test_python_xxe_lxml_safe() -> None:
    code = """
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)
tree = etree.parse("data.xml", parser)
    """
    rule = PythonXXERule()
    finding = rule.scan(code, "app.py")
    assert finding is None


def test_python_xxe_elementtree() -> None:
    code = """
import xml.etree.ElementTree as ET
tree = ET.parse("data.xml")
    """
    rule = PythonXXERule()
    finding = rule.scan(code, "app.py")
    assert finding is not None


def test_python_xxe_defusedxml() -> None:
    code = """
import defusedxml.ElementTree as ET
tree = ET.parse("data.xml")
    """
    rule = PythonXXERule()
    finding = rule.scan(code, "app.py")
    assert finding is None


def test_java_xxe() -> None:
    code = """
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;

public class XMLParser {
    public void parseXML() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
    }
}
    """
    rule = JavaXXERule()
    finding = rule.scan(code, "XMLParser.java")
    assert finding is not None


def test_java_xxe_safe() -> None:
    code = """
import javax.xml.parsers.DocumentBuilderFactory;

public class XMLParser {
    public void parseXML() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();
    }
}
    """
    rule = JavaXXERule()
    finding = rule.scan(code, "XMLParser.java")
    assert finding is None
