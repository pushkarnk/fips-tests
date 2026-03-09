#!/bin/bash

# Make sure the following are installed
# openjdk-{17,21}-jdk
# openjdk-{17,21}-fips-openssl-jre
#

JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64/
JAVA_FIPS_JRE=/usr/lib/jvm/java-21-openjdk-fips-openssl-arm64/

$JAVA_HOME/bin/javac -cp /usr/share/java/openssl-fips-java.jar *.java

$JAVA_FIPS_JRE/bin/java CipherTest
$JAVA_FIPS_JRE/bin/java MacTest
$JAVA_FIPS_JRE/bin/java MDTest
$JAVA_FIPS_JRE/bin/java KeyAgreementTest
$JAVA_FIPS_JRE/bin/java SecretKeyFactoryTest
$JAVA_FIPS_JRE/bin/java SecureRandomTest
$JAVA_FIPS_JRE/bin/java SignatureTest