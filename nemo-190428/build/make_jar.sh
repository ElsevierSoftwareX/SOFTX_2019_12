#!/bin/sh
#JAR=/opt/java/jdk1.7.0_03/bin/jar
JAR=jar
CLASS_PATH=classes
LIB_PATH=lib
echo :
echo : -------------------- MAKE NEMO JAR --------------------
echo :

$JAR -cf $LIB_PATH/nemo.jar -C .$CLASS_PATH it -C $CLASS_PATH org -C $CLASS_PATH java -C $CLASS_PATH test