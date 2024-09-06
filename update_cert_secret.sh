#!/bin/bash

# Check if exactly two arguments are provided
if [ "$#" -ne 1 ]; then
  # echo "Usage: $0 <path-to-cert-file> <path-to-key-file> <domain>"
  echo "Usage: $0 <domain>"
  exit 1
fi

domain="$1"

cert_file=/etc/letsencrypt/live/$domain/fullchain.pem
key_file=/etc/letsencrypt/live/$domain/privkey.pem
working_dir=$(pwd)

# Check if the files exist
if [ ! -f "$cert_file" ] || [ ! -f "$key_file" ]; then
  echo "One or both files do not exist."
  exit 1
fi

cert_content=$(cat "$cert_file")
key_content=$(cat "$key_file")

# Convert files to Base64 without line wrapping
cert_base64=$(echo -ne "$cert_content" | base64 -w 0)
key_base64=$(echo -ne "$key_content" | base64 -w 0)

# Create the YAML content
yaml_content=$(cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: nginx-cert
  namespace: ipchecker
type: Opaque
data:
  nginx.crt: $cert_base64
  nginx.key: $key_base64
EOF
)

# Write the YAML content to a file
output_file="deployment_files/nginx-cert-secret.yaml"
echo "$yaml_content" > "$output_file"

# Print a success message
echo "YAML file '$output_file' has been created successfully."



# Certificate is saved at: /etc/letsencrypt/live/ipchecker.dns-dynamic.net/fullchain.pem
# Key is saved at:         /etc/letsencrypt/live/ipchecker.dns-dynamic.net/privkey.pem