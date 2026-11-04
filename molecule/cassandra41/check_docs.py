"""Validate repository documentation without Docker socket or live services."""
import json
import pathlib
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'molecule/cassandra41'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    readme = (ROOT / 'README.adoc').read_text()
    blocks = re.findall(r'\[source,yaml\]\n----\n(.*?)\n----', readme, re.S)
    examples = [yaml.safe_load(block) for block in blocks]
    ldap = [example for example in examples if 'ldap_uri' in example]
    require(ldap == [yaml.safe_load((ROOT / 'conf/ldap.yaml').read_text())],
            'README LDAP example must match conf/ldap.yaml')

    source = (ROOT / 'base/src/main/java/com/instaclustr/cassandra/ldap/conf/LdapAuthenticatorConfiguration.java').read_text()
    constants = {name: value or number for name, value, number in re.findall(
        r'public static final (?:String|int)\s+(\w+)\s*=\s*(?:"([^"]*)"|(\d+))', source)}
    for name, default in re.findall(
            r'optional(?:String|Boolean|Int)\(root,\s*(\w+),\s*("[^"]*"|true|false|\w+)\)', source):
        key = constants[name]
        value = default.strip('"') if default.startswith('"') else constants.get(default, default)
        require(f'|{key} |{value} |' in readme, f'Incorrect documented default for {key}')

    ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
    matrix = json.loads((SCENARIO / 'matrix.json').read_text())
    parent = ET.parse(ROOT / 'pom.xml').getroot()
    modules = {entry.text for entry in parent.findall('m:modules/m:module', ns)}
    require(modules == {'base'} | {'cassandra-' + key for key in matrix}, 'Maven module matrix drift')
    for module, config in matrix.items():
        pom = ET.parse(ROOT / ('cassandra-' + module) / 'pom.xml').getroot()
        require(pom.findtext('m:version', namespaces=ns) == config['plugin_version'], module + ': artifact version drift')
        props = {entry.tag.split('}')[-1]: entry.text for entry in pom.findall('m:properties/*', ns)}
        dependency = next(entry for entry in pom.findall('m:dependencies/m:dependency', ns)
                          if entry.findtext('m:artifactId', namespaces=ns) == 'cassandra-all')
        version = dependency.findtext('m:version', namespaces=ns)
        if version.startswith('${'):
            version = props[version[2:-1]]
        require(version == config['version'], module + ': server version drift')
        row = f'|cassandra-{module} |{version} |{config["plugin_version"]} |{config["authenticator"]}'
        require(row in readme, module + ': README version table drift')

    docs = [ROOT / name for name in ('README.adoc', 'ACCESS_SYNC.md', 'agent.md', 'AGENTS.md')]
    docs.append(SCENARIO / 'README.md')
    for doc in docs:
        text = doc.read_text()
        text = re.sub(r'```.*?```', '', text, flags=re.S)
        text = re.sub(r'^----\n.*?^----\s*$', '', text, flags=re.S | re.M)
        links = re.findall(r'\[[^\]]*\]\(([^)]+)\)', text) + re.findall(r'link:([^\s\[]+)\[', text)
        for link in links:
            if re.match(r'^(?:[a-z]+:|#)', link):
                continue
            target = link.split('#', 1)[0]
            require((doc.parent / target).exists(), f'Broken link in {doc.relative_to(ROOT)}: {link}')

    unit_dir = ROOT / 'cassandra-4.1/src/test/java/com/instaclustr/cassandra/ldap/auth'
    unit_count = sum(len(re.findall(r'@Test\b', (unit_dir / (name + '.java')).read_text()))
                     for name in ('AccessPolicyTest', 'LDAPSecurityTest', 'DistributedQueryTest'))
    require(unit_count == 10, 'Update the documented unit-test counts')
    collected = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q',
                                '-p', 'no:cacheprovider', str(SCENARIO / 'test_access.py')],
                               cwd=ROOT, text=True, capture_output=True, check=True)
    require(re.search(r'\b15 tests collected\b', collected.stdout) is not None,
            'Update documented e2e counts and matrix acceptance guard')
    print('Documentation valid: YAML examples, Java defaults, six Maven adapters, local links, 10 unit and 15 e2e cases.')


if __name__ == '__main__':
    main()
