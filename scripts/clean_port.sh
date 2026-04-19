#!/bin/bash
# Clean zombie processes listening on port 2346
PORT=2346
echo "Checking for processes on port $PORT..."
if lsof -Pi :$PORT -t >/dev/null; then
    echo "Killing processes on port $PORT..."
    lsof -ti:$PORT | xargs -r kill -9
    echo "Port $PORT cleaned."
else
    echo "No processes found on port $PORT."
fi
