#!/bin/bash

# Make sure the following are installed
# openjdk-{17,21}-jdk
# openjdk-{17,21}-fips-openssl-jre
#
# Test deps
# junit - apt install junit5

JAVA_HOME=/usr/lib/java-{17,21}-openjdk-{arch}/
JAVA_FIPS_JRE=/usr/lib/java-{17,21}-openjdk-fips-openssl-{arch}/

$JAVA_HOME/bin/javac *.java
$JAVA_FIPS_JRE/bin/java Runner


