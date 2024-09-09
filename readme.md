# BulkIntel - Cybersecurity Investigation Tool

BulkIntel is a web application designed for cybersecurity researchers and analysts. It enables bulk lookups across multiple services, providing a comprehensive view of the security status of IP addresses, URLs, domains, hashes, and user agents. The supported services include:

    AbuseIPDB: Bulk check of IP addresses.
    VirusTotal: Bulk check of IPs, URLs, domains, and file hashes.
    Big Data Cloud: Bulk check of user agents.

## Features

- Kubernetes (K8s) Deployment: The application is designed to be deployed on a Kubernetes cluster using MicroK8s, enabling automatic scaling, self-healing, and efficient resource management.
- Containerized Architecture: BulkIntel uses Docker containers, which ensure consistency between different environments and simplify the deployment process.
- Email Allowlist: Only users with allowed emails can register on the platform, ensuring controlled access. One account per email is enforced.
- Bulk Lookup: Quickly query IPs, URLs, domains, and more across various cybersecurity APIs to assist in large-scale investigations.

## Requirements

To deploy BulkIntel, the following requirements must be met:

- Operating System: Ubuntu 22.04 (other distributions may work but have not been tested).
- Docker: For containerized deployment.
- MicroK8s: Kubernetes-based deployment platform.
- API Keys: You will need valid API keys from:
    - AbuseIPDB: https://www.abuseipdb.com/
    - VirusTotal: https://www.virustotal.com
    - Big Data Cloud: https://www.bigdatacloud.com

PD: No need to pay for the API key, the free ones work well. Just take into consideration their limitations

## Deployment Instructions

1. Install Docker on your system by following the instructions on the official Docker website:
[Install Docker](https://docs.docker.com/get-docker/)

2. Install MicroK8s using the following command:

```bash
sudo snap install microk8s --classic
```

3. Clone the Repository

    Clone the BulkIntel repository to your server:

```bash
git clone <repository-url>
```

4. Enter the Project Directory

    Navigate into the cloned repository’s directory:

```bash
cd bulkintel
```

5. Make the Deployment Script Executable

    Give the deployment script the necessary permissions to execute:

```bash
chmod +x deployment.sh
```

6. Run the Deployment Script

    To deploy the application, run the deployment script:

```bash
sudo ./deployment.sh
```

The script will ask for the host's IP address and the API keys for each service (AbuseIPDB, VirusTotal, and Big Data Cloud).
It will automatically build the Docker image, push it to the local MicroK8s repository, and deploy the Kubernetes resources.

### Verify the Deployment

Check the status of your Deployment:
```bash
microk8s kubectl get deployments -n bulkintel
```

Check the status of the pods:
```bash
microk8s kubectl get pods -n bulkintel
```

View logs of the pod:

```bash
microk8s kubectl logs <pod-name> -n bulkintel
```

## Default Credentials

After the application is deployed, the default credentials to access the admin panel are:

    Username: admin
    Password: &6RcyGqxvd6hQ9

It is highly recommended that you change the default password after your first login.

## Email Allowlist Management

BulkIntel enforces a security policy where user registration is restricted to emails that are on an allowlist. Additionally, only one account can be registered per email address.

**To manage the allowlist:**

    Access the admin interface at:

    https://<IP_of_the_machine>:32555/admin/

    Log in using the default credentials.

    Select the "Allowed emails" section.

    Click on the "ADD ALLOWED EMAIL" button to add new emails to the allowlist.

Once an email is added, users can register accounts using that email.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

### MIT License