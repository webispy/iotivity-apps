#!/bin/sh
set -e

SCRIPT_PATH=$1
DAT_PATH=$2
TARGET=$3
TOOL="$(basename $0)"
TIMESTAMP=`date -R`

if [ $# -ne 3 ]; then
	echo "Usage: ${0} <script-path> <dat-file-path> <output-path>"
	exit 0
fi

if [ ! -d ${SCRIPT_PATH} ]; then
	echo "Invalid path: ${SCRIPT_PATH}"
	exit 1
fi

if [ ! -d ${DAT_PATH} ]; then
	echo "Invalid path: ${DAT_PATH}"
	exit 1
fi

echo "- Script path: ${SCRIPT_PATH}"
echo "- DAT path: ${DAT_PATH}"
echo "- Output file: ${TARGET}"

cd $SCRIPT_PATH
cat tpl_head.c > ${TARGET}
cd - > /dev/null

cd ${DAT_PATH}
xxd -i server_svr_db.dat >> ${TARGET}
xxd -i client_svr_db.dat >> ${TARGET}
xxd -i obt_svr_db.dat >> ${TARGET}
cd - > /dev/null

sed -i "s/^  /\t/" ${TARGET}
sed -i "s/unsigned/static unsigned/" ${TARGET}
sed -i "s/{tool}/${TOOL}/" ${TARGET}
sed -i "s/{timestamp}/${TIMESTAMP}/" ${TARGET}

cd $SCRIPT_PATH
cat tpl_foot.c >> ${TARGET}
cd - > /dev/null

exit 0
