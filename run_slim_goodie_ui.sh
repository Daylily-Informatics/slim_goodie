#!/bin/bash

echo "usage: IP:0.0.0.0 PORT:8918 
# Check if $1 is null and set host accordingly
if [ -z "$1" ]; then
  host="0.0.0.0"
else
  host="$1"
fi


# Check if $1 is null and set host accordingly
if [ -z "$2" ]; then
  port="8918"
else
  host="$1"
fi

# Detect the number of CPU cores
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  num_cores=$(nproc)
elif [[ "$OSTYPE" == "darwin"* ]]; then
  num_cores=$(sysctl -n hw.ncpu)
else
  echo "Unsupported OS type: $OSTYPE"
  exit 1
fi

# Calculate the number of workers (2 * number of cores) - 1
num_workers=$(( (num_cores * 2) - 1 ))

# Run Uvicorn for development or Gunicorn for production
if [ -z "$3" ]; then
  echo "Running in dev mode with 1 worker on $host"
  sleep 2
  uvicorn main:app --reload --log-level trace --port $PORT --timeout-keep-alive 303 --host $host
else
  echo "RUNNING IN PRODUCTION MODE"
  echo "Running with $num_workers workers on $host"
  sleep 4
  gunicorn main:app -w $num_workers -k uvicorn.workers.UvicornWorker --log-level trace --timeout 303 --bind $host:$PORT
fi
