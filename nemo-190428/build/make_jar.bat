@echo off
rem set JAR=c:\programmi\java\j2sdk1.4.2_13\bin\jar
set JAR=jar
set CLASS_PATH=classes
set LIB_PATH=lib
echo :
echo : ------------------ MAKE NEMO JAR ------------------
echo :
@echo on
%JAR% -cf %LIB_PATH%/nemo.jar -C %CLASS_PATH% it -C %CLASS_PATH% org -C %CLASS_PATH% java -C %CLASS_PATH% test
