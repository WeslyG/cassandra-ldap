MAVEN_USER_HOME ?= $(CURDIR)/.m2
MAVEN_REPO_LOCAL ?= $(MAVEN_USER_HOME)/repository
MVNW := ./mvnw
JAVA_BUILD_IMAGE ?= maven:3.9.9-eclipse-temurin-17

.PHONY: clean-4.1 build-4.1

.PHONY: integration-4.1 integration-4.1-destroy

.PHONY: build-all test-unit test-release check-docs integration-all release-package

build-all:
	docker run --rm -v "$(CURDIR):/work" -w /work $(JAVA_BUILD_IMAGE) mvn -B -s .mvn/matrix-settings.xml -Dmaven.repo.local=/work/.m2/repository -DskipTests -Dmaven.javadoc.skip=true package

integration-all: build-all
	$(MAKE) test-unit
	$(MAKE) test-release
	$(MAKE) check-docs
	bash molecule/integration/run.sh matrix

test-release:
	docker build -t cassandra-ldap-integration-runner -f molecule/integration/Dockerfile molecule/integration
	docker run --rm -v "$(CURDIR):/work:ro" -w /work --entrypoint python3 cassandra-ldap-integration-runner -m unittest discover -s scripts/tests -v

release-package:
	docker build -t cassandra-ldap-integration-runner -f molecule/integration/Dockerfile molecule/integration
	docker run --rm -v "$(CURDIR):/work" -w /work -e RELEASE_TAG -e GITHUB_REPOSITORY --entrypoint python3 cassandra-ldap-integration-runner scripts/package_release.py

check-docs:
	docker build -t cassandra-ldap-integration-runner -f molecule/integration/Dockerfile molecule/integration
	docker run --rm -v "$(CURDIR):/work:ro" -w /work --entrypoint python3 cassandra-ldap-integration-runner molecule/integration/check_docs.py

test-unit:
	docker run --rm -v "$(CURDIR):/work" -w /work $(JAVA_BUILD_IMAGE) mvn -B -s .mvn/matrix-settings.xml -Dmaven.repo.local=/work/.m2/repository -pl cassandra-4.1 -am -Dtest=AccessPolicyTest,LDAPSecurityTest,DistributedQueryTest -Dsurefire.failIfNoSpecifiedTests=false test

integration-4.1: build-4.1
	bash molecule/integration/run.sh test

integration-4.1-destroy:
	bash molecule/integration/run.sh destroy

clean-4.1:
	rm -rf "$(CURDIR)/base/target"
	rm -rf "$(CURDIR)/cassandra-4.1/target"

build-4.1:
	MAVEN_USER_HOME="$(MAVEN_USER_HOME)" $(MVNW) -pl cassandra-4.1 -am -DskipTests -Dmaven.repo.local="$(MAVEN_REPO_LOCAL)" install
