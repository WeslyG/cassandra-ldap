FROM weslyg/ansible-infra:ansible12-2026.11.04@sha256:2e4896e429bf91b55726adc170e0bd4a1111c5a91343f93379ad01002ac9c6ec
COPY requirements.txt /tmp/ldap-integration-requirements.txt
RUN python3 -m pip install --no-cache-dir -r /tmp/ldap-integration-requirements.txt
ENV LDAP_INTEGRATION_RUNNER=1
