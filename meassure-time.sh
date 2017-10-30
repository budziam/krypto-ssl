#!/usr/bin/env bash

CIPHER="abc123"
DATASET_PATH="./storage/datasets"
OUTPUT_PATH="./storage/output"
FILES=$( ls -Sr ${DATASET_PATH} )

for FILE in ${FILES}
do
  echo "> ${FILE} - BLOWFISH - encryption"
  time ./blowfish -enc -cbc "${DATASET_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.enc" ${CIPHER}

  echo "> ${FILE} - BLOWFISH - decryption"
  time ./blowfish -dec -cbc "${OUTPUT_PATH}/${FILE}.enc" "${OUTPUT_PATH}/${FILE}.dec" ${CIPHER}

  gen-keys "${OUTPUT_PATH}/private-1024" "${OUTPUT_PATH}/public-1024" 1024 > /dev/null
  echo "> ${FILE} - RSA 1024 - encryption"
  time main-rsa "${DATASET_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.enc" "${OUTPUT_PATH}/public-1024" -encrypt

  echo "> ${FILE} - RSA 1024 - decryption"
  time main-rsa "${OUTPUT_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.dec" "${OUTPUT_PATH}/private-1024" -decrypt

  gen-keys "${OUTPUT_PATH}/private-2048" "${OUTPUT_PATH}/public-2048" 2048 > /dev/null
  echo "> ${FILE} - RSA 2048 - encryption"
  time main-rsa "${DATASET_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.enc" "${OUTPUT_PATH}/public-2048" -encrypt

  echo "> ${FILE} - RSA 2048 - decryption"
  time main-rsa "${OUTPUT_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.dec" "${OUTPUT_PATH}/private-2048" -decrypt

  gen-keys "${OUTPUT_PATH}/private-4096" "${OUTPUT_PATH}/public-4096" 4096 > /dev/null
  echo "> ${FILE} - RSA 4096 - encryption"
  time main-rsa "${DATASET_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.enc" "${OUTPUT_PATH}/public-4096" -encrypt

  echo "> ${FILE} - RSA 4096 - decryption"
  time main-rsa "${OUTPUT_PATH}/${FILE}" "${OUTPUT_PATH}/${FILE}.dec" "${OUTPUT_PATH}/private-4096" -decrypt

done
