# DevSecOps Pipeline - Spring Boot PetClinic

Application Spring Boot avec pipeline DevSecOps complet.

## 🛡️ Sécurité Intégrée

- **SAST**: SonarQube
- **SCA**: OWASP Dependency Check
- **Secrets Scan**: Gitleaks
- **Container Security**: Docker Scan
- **DAST**: Tests dynamiques

## 🚀 Déploiement

```bash
# Build
mvn clean package

# Docker
docker build -t petclinic:latest .

# Kubernetes
kubectl apply -f deployment.yaml
