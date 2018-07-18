#

docker build -t mzahorik/f5-ctlr:latest .
if [ $? != 0 ]; then
  echo "Build failure"
  exit 1
fi
