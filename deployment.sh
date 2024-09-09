#!/bin/bash

# Prompt the user for the IP address
read -p "Please enter your IP address: " IP

# Prompt the user for the API key
read -p "Please enter your AbuseIPDB API key: " abuse_ipdb_api_key
read -p "Please enter your VirusTotal API key: " virus_total_api_key
read -p "Please enter your Big Data Cloud API key: " big_data_api_key

# Get the current working directory
current_dir=$(pwd)

# Function to create namespace if it doesn't exist
create_namespace() {
  local ns=$1
  if ! microk8s kubectl get namespace "$ns" > /dev/null 2>&1; then
    echo "Namespace $ns not found. Creating namespace..."
    microk8s kubectl create namespace "$ns"
  else
    echo "Namespace $ns already exists."
  fi
}

check_and_enable_microk8s_services() {
    services=("dns" "registry")
    for service in "${services[@]}"; do
        if microk8s status --format short | grep -q "${service}: enabled"; then
            echo "${service} is already enabled."
        else
            echo "${service} is not enabled. Enabling ${service}..."
            microk8s enable "${service}"
            if [ $? -eq 0 ]; then
                echo "${service} enabled successfully."
            else
                echo "Failed to enable ${service}."
            fi
        fi
    done
}

# Check if metrics-server is enabled
if ! microk8s status | grep -q "metrics-server: enabled"; then
  echo "Enabling metrics-server..."
  microk8s enable metrics-server
else
  echo "metrics-server is already enabled."
fi

check_and_enable_microk8s_services

# Convert the API key to base64
abuse_ipdb_key=$(echo -n "$abuse_ipdb_api_key" | base64 -w 0)
virus_total_key=$(echo -n "$virus_total_api_key" | base64 -w 0)
big_data_key=$(echo -n "$big_data_api_key" | base64 -w 0)

# YML template (use a heredoc for the file content)
cat <<EOF > deployment_files/secrets.yml
apiVersion: v1
kind: Secret
metadata:
  name: bulkintelsecrets
  namespace: bulkintel
type: Opaque
data:
  SECRET_KEY: "ZGphbmdvLWluc2VjdXJlLXgwcWdodTApendqej05eF8tXmhsN3VwcyQ3emdAQHlrNylpdXcrJjJrZiF6dm5qejNe"
  ABUSEIPDB_KEY: $abuse_ipdb_key
  VIRUSTOTAL_KEY: $virus_total_key
  BIG_DATA_USERAGENT_KEY: $big_data_key
EOF

echo "secrets.yml has been created with the base64-encoded AbuseIPDB API key."

# YML template (use a heredoc for the file content)
cat <<EOF > deployment_files/nginx-config.yml
apiVersion: v1
kind: ConfigMap
metadata:
    name: nginx-config
    namespace: bulkintel
data:
    nginx.conf: |
        worker_processes 1;

        events {
            worker_connections 1024;
        }

        http {
            upstream django {
                server bulkintel:9005;
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
                    proxy_pass http://bulkintel:9005;
                    proxy_set_header Host \$host;
                    proxy_set_header X-Real-IP \$remote_addr;
                    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto \$scheme;
                }
            }
        }
EOF

echo "nginx-config.yml has been created with the provided IP address."


# File path to settings.py (adjust if needed)
SETTINGS_FILE="bulkintel/settings.py"

# Replace ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS in the settings.py file
sed -i "/^ALLOWED_HOSTS/c\ALLOWED_HOSTS = ['localhost', '127.0.0.1', '$IP']" "$SETTINGS_FILE"

sed -i "/^CSRF_TRUSTED_ORIGINS/c\CSRF_TRUSTED_ORIGINS = ['https://localhost', 'https://$IP', 'https://127.0.0.1', 'https://localhost:32555', 'https://$IP:32555', 'https://127.0.0.1:32555']" "$SETTINGS_FILE"

echo "IP address has been added to ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS in $SETTINGS_FILE"

# Replacing the working directory for the mount in Nginx deployment
cat <<EOF > deployment_files/nginx_deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: bulkintel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        resources:
          requests:
            cpu: "50m" # Minimum CPU resources required
          limits:
            cpu: "200m" # Maximum CPU resources allowed
        ports:
        - containerPort: 443
        volumeMounts:
        - name: certs
          mountPath: /etc/nginx/certs
        - name: nginx-conf
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf  # Ensure this matches the key in the ConfigMap
        - name: staticfiles
          mountPath: /code/staticfiles
      volumes:
      - name: certs
        secret:
          secretName: nginx-certs
      - name: nginx-conf
        configMap:
          name: nginx-config
      - name: staticfiles
        hostPath:
          path: $current_dir/staticfiles
EOF

echo "nginx_deployment.yml has been created with the current working directory."

# Replacing the working directory for the mount in IP checker deployment
cat <<EOF > deployment_files/deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bulkintel
  namespace: bulkintel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: bulkintel
  template:
    metadata:
      labels:
        app: bulkintel
    spec:
      containers:
      - name: bulkintel
        image: localhost:32000/bulkintel:v1
        resources:
          requests:
            cpu: "100m" # Minimum CPU resources required
          limits:
            cpu: "500m" # Maximum CPU resources allowed
        command: ["/bin/sh","-c"]
        args: ["python manage.py migrate && gunicorn --workers 3 --bind 0.0.0.0:9005 bulkintel.wsgi:application"]
        volumeMounts:
        - name: sqlite-storage
          mountPath: /data
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: bulkintelsecrets
              key: SECRET_KEY
        - name: ABUSEIPDB_KEY
          valueFrom:
            secretKeyRef:
              name: bulkintelsecrets
              key: ABUSEIPDB_KEY
        - name: VIRUSTOTAL_KEY
          valueFrom:
            secretKeyRef:
              name: bulkintelsecrets
              key: VIRUSTOTAL_KEY
        - name: BIG_DATA_USERAGENT_KEY
          valueFrom:
            secretKeyRef:
              name: bulkintelsecrets
              key: BIG_DATA_USERAGENT_KEY
        ports:
        - containerPort: 9005
      volumes:
      - name: sqlite-storage
        hostPath:
          path: $current_dir/data
EOF

echo "deployment.yml has been created with the current working directory."

# Check if SSL certificates exist
if [[ ! -f "nginx-selfsigned.key" || ! -f "nginx-selfsigned.crt" ]]; then
  echo "SSL certificates not found. Generating new ones..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./nginx-selfsigned.key -out ./nginx-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"
else
  echo "SSL certificates already exist."
fi

# Build and push the docker image to the local repository
docker build -t localhost:32000/bulkintel:v1 . # Change the image name before releae

docker push localhost:32000/bulkintel:v1 # Change the image name before releae

# Create the bulkintel namespace if it doesn't exist
create_namespace "bulkintel"

# Apply the YML files and configurations
echo "Applying Kubernetes configurations..."

microk8s kubectl apply -f deployment_files/secrets.yml
sleep 2

microk8s kubectl apply -f deployment_files/deployment.yml
sleep 5

microk8s kubectl apply -f deployment_files/bulkintel_service.yml
sleep 2

microk8s kubectl apply -f deployment_files/bulkintel_hpa.yml
sleep 2

microk8s kubectl create secret generic nginx-certs --from-file=nginx-selfsigned.crt --from-file=nginx-selfsigned.key --namespace=bulkintel
sleep 2

microk8s kubectl apply -f deployment_files/nginx-config.yml
sleep 2

microk8s kubectl apply -f deployment_files/nginx_deployment.yml
sleep 5

microk8s kubectl apply -f deployment_files/nginx_service.yml
sleep 2

microk8s kubectl apply -f deployment_files/nginx_hpa.yml
sleep 2

microk8s kubectl apply -f deployment_files/redis-deployment.yml
sleep 5

microk8s kubectl apply -f deployment_files/redis-service.yml
sleep 2

echo "Deployment completed successfully."
