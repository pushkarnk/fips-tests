#!/bin/bash

# Make sure the following are installed
# openjdk-{17,21}-jdk
# openjdk-{17,21}-fips-openssl-jre
#
# Test deps
# junit - apt install junit5

JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64/
JAVA_FIPS_JRE=/usr/lib/jvm/java-17-openjdk-fips-openssl-arm64/

$JAVA_HOME/bin/javac -cp /usr/share/java/junit-jupiter-api.jar:/usr/share/java/junit-jupiter-params.jar:/usr/share/java/junit4.jar *.java
$JAVA_FIPS_JRE/bin/java -cp /usr/share/java/junit-jupiter-api.jar:/usr/share/java/junit-jupiter-params.jar:/usr/share/java/junit4.jar Runner
