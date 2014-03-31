#!/bin/sh
rm -f dirg_util*
sphinx-apidoc -F -o ../doc/ ../src/dirg_util
make clean
make html