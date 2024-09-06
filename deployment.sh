#!/bin/bash

# Prompt the user for the IP address
read -p "Please enter your IP address: " IP

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

# Check if metrics-server is enabled
if ! microk8s status | grep -q "metrics-server: enabled"; then
  echo "Enabling metrics-server..."
  microk8s enable metrics-server
else
  echo "metrics-server is already enabled."
fi

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

# Replacing the working directory for the mount in Nginx deployment
cat <<EOF > nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
  namespace: ipchecker-pre-release
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

echo "nginx-deployment.yaml has been created with the current working directory."

# Replacing the working directory for the mount in IP checker deployment
cat <<EOF > ipchecker-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ipchecker
  namespace: ipchecker-pre-release
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ipchecker
  template:
    metadata:
      labels:
        app: ipchecker
    spec:
      containers:
      - name: ipchecker
        image: localhost:32000/ipchecker:v2
        resources:
          requests:
            cpu: "100m" # Minimum CPU resources required
          limits:
            cpu: "500m" # Maximum CPU resources allowed
        command: ["/bin/sh","-c"]
        args: ["doppler run -- python manage.py migrate && doppler run -- gunicorn --workers 3 --bind 0.0.0.0:9005 ip_checker.wsgi:application"]
        volumeMounts:
        - name: sqlite-storage
          mountPath: /data
        env:
        - name: DOPPLER_TOKEN
          valueFrom:
            secretKeyRef:
              name: doppler-token
              key: DOPPLER_TOKEN
        ports:
        - containerPort: 9005
      volumes:
      - name: sqlite-storage
        hostPath:
          path: $current_dir/data
EOF

echo "ipchecker-deployment.yaml has been created with the current working directory."

# Check if SSL certificates exist
if [[ ! -f "nginx-selfsigned.key" || ! -f "nginx-selfsigned.crt" ]]; then
  echo "SSL certificates not found. Generating new ones..."
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout ./nginx-selfsigned.key -out ./nginx-selfsigned.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"
else
  echo "SSL certificates already exist."
fi

# Create the ipchecker namespace if it doesn't exist
create_namespace "ipchecker-pre-release"

# Apply the YAML files and configurations
echo "Applying Kubernetes configurations..."

microk8s kubectl apply -f deployment_files/secrets.yml
sleep 2

microk8s kubectl apply -f deployment_files/deployment.yml
sleep 5

microk8s kubectl apply -f deployment_files/ipchecker_service.yml
sleep 2

microk8s kubectl apply -f deployment_files/ipchecker_hpa.yml
sleep 2

microk8s kubectl create secret generic nginx-certs --from-file=nginx-selfsigned.crt --from-file=nginx-selfsigned.key --namespace=ipchecker-pre-release
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
