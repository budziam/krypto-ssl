#!/usr/bin/env bash

CIPHER="abc123"
PATH="./storage"
FILES=$( ls ${PATH} )

for FILE in ${FILES}
do
  echo "> ${FILE} - encryption"
  time ./blowfish -enc -cbc "${PATH}/${FILE}" "${PATH}/${FILE}.enc" ${CIPHER}

  echo "> ${FILE} - decryption"
  time ./blowfish -dec -cbc "${PATH}/${FILE}.enc" "${PATH}/${FILE}.dec" ${CIPHER}
done
