#!/bin/bash

# Make sure the following are installed
# openjdk-{17,21}-jdk
# openjdk-{17,21}-fips-openssl-jre
# Also, JAVA_HOME and JAVA_FIPS_JRE should be defined.

$JAVA_HOME/bin/javac -cp /usr/share/java/openssl-fips-java.jar *.java

$JAVA_FIPS_JRE/bin/java CipherTest
$JAVA_FIPS_JRE/bin/java MacTest
$JAVA_FIPS_JRE/bin/java MDTest
$JAVA_FIPS_JRE/bin/java KeyAgreementTest
$JAVA_FIPS_JRE/bin/java SecretKeyFactoryTest
$JAVA_FIPS_JRE/bin/java SecureRandomTest
$JAVA_FIPS_JRE/bin/java SignatureTest
$JAVA_FIPS_JRE/bin/java KeyConverterTest
$JAVA_FIPS_JRE/bin/java KeyPairGeneratorSpecTest
$JAVA_FIPS_JRE/bin/java RSAKeyPairGeneratorTest
$JAVA_FIPS_JRE/bin/java PSSParameterTest
$JAVA_FIPS_JRE/bin/java ProviderSanityTest
