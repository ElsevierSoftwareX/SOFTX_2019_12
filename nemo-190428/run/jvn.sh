#!/bin/sh
java -Xbootclasspath/p:lib/nemo.jar -Dsun.boot.library.path=lib -Djava.library.path=lib $*
