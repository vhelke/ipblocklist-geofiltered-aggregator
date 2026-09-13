#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

# Safely load environment variables from .env while ignoring comments and empty lines
while IFS='=' read -r key value; do
  # Ignore lines that are comments or empty
  if [[ ! "$key" =~ ^# && -n "$key" ]]; then
    export "$key=$value"
  fi
done < .env

# Where to save raw files
INPUT_DIR="/data/input"
COMBINED_INPUT="/tmp/all_input.txt"
OUTPUT_DIR="/data/output"

# Create the input and output directories if they don't exist
mkdir -p "$INPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Clear the OUTPUT_DIR before generating new output files
echo "[INFO] Clearing output directory $OUTPUT_DIR before generating new files..."
rm -rf "$OUTPUT_DIR"/*

# Load LIST variables dynamically into an array (supports LIST_#, LIST_VPS#, LIST_DATA#, etc.)
LISTS=()
for var in $(env | grep '^LIST_' | cut -d= -f1); do
  LISTS+=("${!var}")  # Append value of each LIST_ variable to the LISTS array
done

# Ensure the LISTS array is populated
if [ ${#LISTS[@]} -eq 0 ]; then
  echo "[ERROR] No LIST URLs found in the environment variables!"
  exit 1
fi

# Download files
echo "[INFO] Downloading ${#LISTS[@]} files..."
for url in "${LISTS[@]}"; do
  fname="$(basename "$url")"  # Extract the file name from the URL
  echo "[INFO] → $url → $INPUT_DIR/$fname"
  
  # Download and save file
  if ! wget -q -O "$INPUT_DIR/$fname" "$url"; then
    echo "[WARNING] Failed to download file from $url, skipping..."
    continue
  fi
done

# Check if any files were downloaded
if [ ! "$(ls -A $INPUT_DIR 2>/dev/null)" ]; then
  echo "[ERROR] No files were successfully downloaded!"
  exit 1
fi

# Combine all downloaded files into one input file
echo "[INFO] Combining all downloaded files..."
> "$COMBINED_INPUT"  # Create/clear the combined input file

for file in "$INPUT_DIR"/*; do
  if [ -f "$file" ]; then
    echo "[INFO] Adding $(basename "$file")..."
    # Add file content and ensure it ends with a newline
    cat "$file" >> "$COMBINED_INPUT"
    echo "" >> "$COMBINED_INPUT"
  fi
done

# Check if combined file has content
if [[ ! -s "$COMBINED_INPUT" ]]; then
  echo "[ERROR] Combined input file is empty!"
  exit 1
fi

echo "[INFO] Combined $(wc -l < "$COMBINED_INPUT") lines from all sources"

# Run the aggregation script with stdin input
echo "[INFO] Running IP aggregation..."
if ! python /app/__main__.py -s < "$COMBINED_INPUT" > "$OUTPUT_DIR/aggregated.txt" 2>/dev/null; then
  echo "[ERROR] IP aggregation failed!"
  exit 1
fi

echo "[INFO] Aggregation complete: $(wc -l < "$OUTPUT_DIR/aggregated.txt") unique networks/IPs"

# ---------------------------------------------------------------------------
# GeoIP exclusion filtering
# ---------------------------------------------------------------------------

echo "[INFO] Running GeoIP country exclusion filtering..."

if ! python /app/filter_ips.py; then
    echo "[ERROR] GeoIP filtering failed!"
    exit 1
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

echo "[INFO] Cleaning up temporary files..."

rm -rf "$INPUT_DIR"
rm -f "$COMBINED_INPUT"

echo "[INFO] Processing complete!"

echo "[INFO] Results:"

if [ -f "$OUTPUT_DIR/aggregated.txt" ]; then
    echo "[INFO] Original aggregated list:"
    echo "       $(wc -l < "$OUTPUT_DIR/aggregated.txt") entries"
fi

if [ -f "$OUTPUT_DIR/aggregated-vyos.txt" ]; then
    echo "[INFO] VyOS filtered list:"
    echo "       $(wc -l < "$OUTPUT_DIR/aggregated-vyos.txt") entries"
fi
