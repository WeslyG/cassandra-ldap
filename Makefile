JAVA_HOME ?= /opt/homebrew/opt/openjdk
MAVEN_USER_HOME ?= $(CURDIR)/.m2
MAVEN_REPO_LOCAL ?= $(MAVEN_USER_HOME)/repository
MVNW := ./mvnw

.PHONY: clean-4.1 build-4.1

clean-4.1:
	rm -rf "$(CURDIR)/base/target"
	rm -rf "$(CURDIR)/cassandra-4.1/target"

build-4.1:
	JAVA_HOME="$(JAVA_HOME)" MAVEN_USER_HOME="$(MAVEN_USER_HOME)" $(MVNW) -pl cassandra-4.1 -am -DskipTests -Dmaven.repo.local="$(MAVEN_REPO_LOCAL)" install
