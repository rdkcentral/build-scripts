#!/bin/sh

SCRIPT_DIR=$(dirname "$0")
BITBAKE_ENV_FILE="$1"
INC_FILE="$2"

if [ ! -f "$BITBAKE_ENV_FILE" ]; then
   echo "ERROR: BitBake environment file not found: $BITBAKE_ENV_FILE"
   exit 1
fi

CVE_LAYER_FEED_PATH=$(grep '^CVE_LAYER_FEED_PATH=' "$BITBAKE_ENV_FILE" | cut -d'"' -f2)

# normalize spaces
CVE_LAYER_FEED_PATH=$(echo "$CVE_LAYER_FEED_PATH" | xargs)

echo "Parsed CVE_LAYER_FEED_PATH:"
echo "$CVE_LAYER_FEED_PATH"

for entry in $CVE_LAYER_FEED_PATH; do
    [ -z "$entry" ] && continue

    #NAME=$(echo "$entry" | cut -d'#' -f1)
    URL=$(echo "$entry" | sed -e 's/.*##//' -e 's/;.*//')
    echo "Processing: $NAME"
    echo "URL: $URL"

    # Try header first
        SHA=$(curl --netrc -sI -L "$URL" \
                | awk -F': ' '/X-Checksum-Sha256/ {print $2}' \
                | tr -d '\r')

    # Skip entry if SHA could not be obtained
    if [ -z "$SHA" ]; then
            echo "WARNING: Failed to fetch SHA for $NAME ($URL) — skipping entry"
            continue
    fi

    #VAR=$(echo "$entry" | sed -n 's/.*sha256sum=${\([^}]*\)}.*/\1/p')
    
 #   echo "ENTRY=$entry"
VAR=$(echo "$entry" | sed -n 's/.*sha256sum=${\([^}]*\)}.*/\1/p')

#echo "VAR=$VAR"

    echo "$VAR = \"$SHA\"" >> "$INC_FILE"
   # UPDATED="$UPDATED $NAME##$URL;sha256sum=$SHA"

done
