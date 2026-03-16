JAVA_HOME ?= /opt/homebrew/opt/openjdk
MAVEN_USER_HOME ?= $(CURDIR)/.m2
MVNW := ./mvnw

.PHONY: build-4.1

build-4.1:
	JAVA_HOME="$(JAVA_HOME)" MAVEN_USER_HOME="$(MAVEN_USER_HOME)" $(MVNW) -pl cassandra-4.1 -am -DskipTests package
