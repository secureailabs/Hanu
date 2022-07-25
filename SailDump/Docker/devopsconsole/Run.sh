#!/bin/bash
imageName=devopsconsole

# Check if docker is installed
docker --version
retVal=$?
if [ $retVal -ne 0 ]; then
  echo "Error docker does not exist"
  exit $retVal
fi

# Check if the image exists
imageNameFound=$(docker image ls --filter reference=$imageName --format {{.Repository}})
echo "$imageNameFound"
if [ "$imageNameFound" == "$imageName" ]; then
  echo "Docker image exists"
else
  echo "!!! Docker image not found !!!"
  exit 1
fi

# Move the InitializerVector to the DevopsConsole folder
mv InitializationVector.json DevopsConsole/

# Run the docker container
docker run \
  -dit \
  --rm \
  -v $(pwd)/DevopsConsole:/app \
  -v $(pwd)/DevopsConsole/nginx:/etc/nginx/conf.d \
  -v $(pwd)/DevopsConsole/certs:/etc/nginx/certs \
  -p 5050:443 \
  --name devops \
  $imageName
