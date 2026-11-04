FROM weslyg/ansible-infra:ansible12-2026.11.04
COPY requirements.txt /tmp/ldap41-requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/ldap41-requirements.txt
ENV LDAP41_RUNNER=1
