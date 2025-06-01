#!/bin/bash

DIRECTORIO="."

for archivo in "$DIRECTORIO"/*.png; do
	numero=$(echo "$archivo" | cut -f 3 -d " ")
	mv "$archivo" "$numero"  
done
