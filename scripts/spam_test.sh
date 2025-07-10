#!/bin/bash

for i in {1..20}; do
echo -e "Subject: Test spam $i\nFrom: spamuser1@example.com\nTo: eliasdavidroman@gmail.com\n\nCuerpo del correo $i" | sendmail -t
done
