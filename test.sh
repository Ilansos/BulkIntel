#!/bin/bash

# Prompt the user for the IP address
read -p "Please enter your IP address: " IP

# YAML template (use a heredoc for the file content)
cat <<EOF > deployment_files/nginx-config.yml
apiVersion: v1
kind: ConfigMap
metadata:
    name: nginx-config
    namespace: ipchecker-pre-release
data:
    nginx.conf: |
        worker_processes 1;

        events {
            worker_connections 1024;
        }

        http {
            upstream django {
                server ipchecker:9005;
            }

            server {
                listen 80;
                server_name $IP;
                
                location / {
                    return 301 https://\$host\$request_uri;
                }
            }

            server {
                listen 443 ssl;
                server_name $IP;

                ssl_certificate /etc/nginx/certs/nginx-selfsigned.crt;
                ssl_certificate_key /etc/nginx/certs/nginx-selfsigned.key;

                location /static/ {
                    alias /code/staticfiles/;
                    types {
                        text/css css;
                        application/javascript js;
                        # other types if necessary
                    }
                }

                location / {
                    proxy_pass http://ipchecker:9005;
                    proxy_set_header Host \$host;
                    proxy_set_header X-Real-IP \$remote_addr;
                    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto \$scheme;
                }
            }
        }
EOF

echo "nginx-config.yaml has been created with the provided IP address."


# File path to settings.py (adjust if needed)
SETTINGS_FILE="ip_checker/settings.py"

# Replace ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS in the settings.py file
sed -i "/^ALLOWED_HOSTS/c\ALLOWED_HOSTS = ['localhost', '127.0.0.1', '$IP']" "$SETTINGS_FILE"

sed -i "/^CSRF_TRUSTED_ORIGINS/c\CSRF_TRUSTED_ORIGINS = ['https://localhost', 'https://$IP', 'https://127.0.0.1', 'https://localhost:32444', 'https://$IP:32444', 'https://127.0.0.1:32444']" "$SETTINGS_FILE"

echo "IP address has been added to ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS in $SETTINGS_FILE"