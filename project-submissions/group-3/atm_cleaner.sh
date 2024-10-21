#!/bin/bash

directories=(
  "cards",
  "auth"
)

for dir in "${directories[@]}"; do
  if [ -d "$dir" ]; then
    echo "Cleaning directory: $dir"
    rm -rf "$dir"/*
  fi
done

echo "Cleaning complete."