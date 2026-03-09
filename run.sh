#!/bin/bash

# Make sure the following are installed
# openjdk-{17,21}-jdk
# openjdk-{17,21}-fips-openssl-jre
#
# Test deps
# junit - apt install junit5

JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/
JAVA_FIPS_JRE=/usr/lib/jvm/java-17-openjdk-fips-openssl-amd64/

$JAVA_HOME/bin/javac *.java

$JAVA_FIPS_JRE/bin/java CipherTest
$JAVA_FIPS_JRE/bin/java MacTest
$JAVA_FIPS_JRE/bin/java MessageDigestTest
$JAVA_FIPS_JRE/bin/java KeyAgreementTest
$JAVA_FIPS_JRE/bin/java KeyFactoryTest
$JAVA_FIPS_JRE/bin/java KeyPairGeneratorTest
$JAVA_FIPS_JRE/bin/java KeyStoreTest
$JAVA_FIPS_JRE/bin/java SecretKeyFactoryTest
$JAVA_FIPS_JRE/bin/java SecureRandomTest
