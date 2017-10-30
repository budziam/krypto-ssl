#!/usr/bin/env bash

CIPHER="abc123"
STORAGE_PATH="./storage"
FILES=$( ls ${STORAGE_PATH} )

for FILE in ${FILES}
do
  echo "> ${FILE} - encryption"
  time ./blowfish -enc -cbc "${STORAGE_PATH}/${FILE}" "${STORAGE_PATH}/${FILE}.enc" ${CIPHER}

  echo "> ${FILE} - decryption"
  time ./blowfish -dec -cbc "${STORAGE_PATH}/${FILE}.enc" "${STORAGE_PATH}/${FILE}.dec" ${CIPHER}
done
