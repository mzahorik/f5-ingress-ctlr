#

docker build --no-cache -t mzahorik/f5-ctlr:latest .
if [ $? != 0 ]; then
  echo "Build failure"
  exit 1
fi
docker tag mzahorik/f5-ctlr:latest mzahorik/f5-ctlr:`cat release.txt`
docker push mzahorik/f5-ctlr:`cat release.txt`
docker push mzahorik/f5-ctlr:latest
