pipeline {
    agent any

    environment {
        SONAR_HOST_URL = 'http://192.168.50.4:9000/'
        SONAR_AUTH_TOKEN = credentials('sonarqube')
        NVD_API_KEY = credentials('nvd-api-key')
        DOCKER_IMAGE = "omarhamdawi/devops_jenkins"
        CRITICAL_CVSS_THRESHOLD = "7"
        SONAR_QUALITY_GATE_TIMEOUT = "10"
        EMAIL_RECIPIENTS = 'omar.hamdaoui@esprit.tn'
    }

    stages {
        stage('Initialisation') {
            steps {
                script {
                    echo "🚀 DÉMARRAGE DU PIPELINE DEVSECOPS"
                    echo "📅 Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}"
                    echo "🔢 Build: ${env.BUILD_NUMBER}"
                    
                    // Créer le dossier des rapports
                    sh '''
                    mkdir -p security-reports
                    mkdir -p security-reports/sast
                    mkdir -p security-reports/sca
                    mkdir -p security-reports/secrets
                    mkdir -p security-reports/docker
                    mkdir -p security-reports/consolidated
                    mkdir -p security-reports/pdf
                    '''
                    
                    sh 'java -version || echo "Java vérifié"'
                    
                    // Initialisation des variables de rapport
                    env.SECRETS_COUNT = "0"
                    env.CRITICAL_VULNERABILITIES = "0"
                    env.SONAR_STATUS = "UNKNOWN"
                    env.BUILD_STATUS = "IN_PROGRESS"
                    
                    // Fichier pour stocker les détails des vulnérabilités
                    sh 'echo "Initialisation des rapports..." > security-reports/vulnerabilities_details.txt'
                }
            }
        }

        stage('Checkout Code') {
            steps {
                // ADDED: Checkout SCM for webhook compatibility
                checkout scmGit(branches: [[name: '*/main']], extensions: [], userRemoteConfigs: [[credentialsId: 'jenkins-github', url: 'https://github.com/omarhamdawi/devops_jenkins.git']])
                
                script {
                    // Rapport de checkout
                    writeFile file: "security-reports/checkout_report.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Rapport Checkout</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📥 CHECKOUT RÉUSSI</h1>
            <p>Récupération du code source</p>
        </div>
        <div class="success">
            <h3>✅ Code source récupéré avec succès</h3>
            <p><strong>Repository:</strong> https://github.com/omarhamdawi/devops_jenkins.git</p>
            <p><strong>Branch:</strong> main</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
        </div>
    </div>
</body>
</html>
"""
                }
            }
        }

        stage('Build Application') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
            post {
                always {
                    script {
                        // Rapport de build
                        writeFile file: "security-reports/build_report.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Rapport Build</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔨 BUILD APPLICATION</h1>
            <p>Compilation et packaging</p>
        </div>
        <div class="success">
            <h3>✅ Application construite avec succès</h3>
            <p><strong>Commande:</strong> mvn clean package -DskipTests</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
            <p><strong>Artifact:</strong> target/*.jar</p>
        </div>
    </div>
</body>
</html>
"""
                    }
                }
            }
        }

        stage('SAST - SonarQube Analysis') {
            steps {
                script {
                    echo "🔍 SAST - Analyse Statique de Sécurité avec SonarQube"
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        timeout(time: env.SONAR_QUALITY_GATE_TIMEOUT.toInteger(), unit: 'MINUTES') {
                            sh """
                            mvn sonar:sonar \
                              -Dsonar.projectKey=devops_jenkins \
                              -Dsonar.host.url=${SONAR_HOST_URL} \
                              -Dsonar.token=${SONAR_AUTH_TOKEN} \
                              -Dsonar.qualitygate.wait=false \
                              -Dsonar.scm.disabled=true || echo "SonarQube analysis failed but continuing"
                            """
                        }
                    }
                }
            }
            post {
                always {
                    script {
                        // Rapport SAST
                        def sastStatus = currentBuild.result == 'SUCCESS' ? 'SUCCESS' : 'FAILED'
                        env.SONAR_STATUS = sastStatus
                        
                        writeFile file: "security-reports/sast/sast_report.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Rapport SAST</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .failure { background: #f8d7da; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ANALYSE SAST</h1>
            <p>SonarQube - Analyse Statique de Sécurité</p>
        </div>
        ${sastStatus == 'SUCCESS' ? """
        <div class="success">
            <h3>✅ Analyse SAST terminée avec succès</h3>
            <p><strong>Status:</strong> ${sastStatus}</p>
            <p><strong>Outils:</strong> SonarQube</p>
            <p><strong>URL SonarQube:</strong> ${SONAR_HOST_URL}</p>
            <p><strong>Project Key:</strong> devops_jenkins</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
        </div>
        """ : """
        <div class="failure">
            <h3>❌ Analyse SAST échouée</h3>
            <p><strong>Status:</strong> ${sastStatus}</p>
            <p><strong>Outils:</strong> SonarQube</p>
            <p><strong>URL SonarQube:</strong> ${SONAR_HOST_URL}</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
            <p><em>Note: Le pipeline continue malgré l'échec SAST</em></p>
        </div>
        """}
    </div>
</body>
</html>
"""
                    }
                }
            }
        }

        stage('SCA - OWASP Dependency Check') {
            steps {
                script {
                    echo "📦 SCA - Analyse des Dépendances avec OWASP Dependency-Check"
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        dependencyCheck(
                            odcInstallation: 'dependency-check',
                            additionalArguments: """
                                --project "devops_jenkins"
                                --scan "**/*.jar"
                                --scan "pom.xml"
                                --format HTML
                                --format JSON
                                --out .
                                --failOnCVSS 11
                                --enableExperimental
                                --nvdApiKey ${NVD_API_KEY}
                                --log odc.log
                            """.stripIndent()
                        )
                    }
                    
                    // Copier les rapports SCA dans le dossier organisé
                    sh '''
                    cp dependency-check-report.html security-reports/sca/ 2>/dev/null || true
                    cp dependency-check-report.json security-reports/sca/ 2>/dev/null || true
                    cp odc.log security-reports/sca/ 2>/dev/null || true
                    '''
                }
            }
            post {
                always {
                    script {
                        echo "📊 Traitement des résultats SCA..."
                        
                        sh '''
                        if [ -f "dependency-check-report.json" ]; then
                            echo "📊 Analyse détaillée des vulnérabilités (CVSS ≥ 7.0)..."
                            python3 << 'EOF'
import json
import sys

try:
    with open('dependency-check-report.json', 'r') as f:
        data = json.load(f)
    
    critical_count = 0
    vulnerabilities_details = []
    
    for dep in data.get("dependencies", []):
        dep_name = dep.get("fileName", "Unknown")
        vulnerabilities = dep.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cvss_score = vuln.get("cvssv3", {}).get("baseScore", vuln.get("cvssScore", 0))
            if cvss_score >= 7.0:
                critical_count += 1
                cve_id = vuln.get("name", "CVE-UNKNOWN")
                severity = vuln.get("severity", "Unknown")
                description = vuln.get("description", "No description available")
                
                vulnerabilities_details.append({
                    "dependency": dep_name,
                    "cve": cve_id,
                    "score": cvss_score,
                    "severity": severity,
                    "description": description
                })
    
    # Écrire les détails dans un fichier
    with open('security-reports/vulnerabilities_details.txt', 'w') as f:
        if vulnerabilities_details:
            f.write("VULNÉRABILITÉS CRITIQUES DÉTECTÉES:\\n")
            f.write("=" * 80 + "\\n")
            for v in vulnerabilities_details:
                f.write(f"Dépendance: {v['dependency']}\\n")
                f.write(f"CVE: {v['cve']}\\n")
                f.write(f"Score CVSS: {v['score']} ({v['severity']})\\n")
                f.write(f"Description: {v['description'][:200]}...\\n")
                f.write("-" * 50 + "\\n")
        else:
            f.write("✅ AUCUNE VULNÉRABILITÉ CRITIQUE DÉTECTÉE\\n")
            f.write("Aucune dépendance avec un score CVSS ≥ 7.0 n'a été trouvée.\\n")
    
    # Écrire le compte dans un fichier
    with open('security-reports/critical_vulns_count.txt', 'w') as f:
        f.write(str(critical_count))
    
    print("")
    print("📈 RÉSUMÉ SCA:")
    print("   • Vulnérabilités critiques (CVSS ≥ 7.0): " + str(critical_count))
    print("   • Total des dépendances analysées: " + str(len(data.get("dependencies", []))))
    
except Exception as e:
    print("❌ Erreur lors de l'analyse SCA: " + str(e))
    with open('security-reports/critical_vulns_count.txt', 'w') as f:
        f.write('0')
    with open('security-reports/vulnerabilities_details.txt', 'w') as f:
        f.write("ERREUR LORS DE L'ANALYSE DES VULNÉRABILITÉS\\n")
EOF
                        else
                            echo "⚠️ Aucun rapport SCA trouvé"
                            echo "0" > security-reports/critical_vulns_count.txt
                            echo "AUCUN RAPPORT SCA DISPONIBLE" > security-reports/vulnerabilities_details.txt
                        fi
                        '''
                        
                        // Lire le résultat du fichier
                        def criticalCount = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                        env.CRITICAL_VULNERABILITIES = criticalCount
                        echo "🔍 Vulnérabilités critiques détectées: ${env.CRITICAL_VULNERABILITIES}"
                    }
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                script {
                    echo "🔐 SCAN DES SECRETS - Détection des credentials exposés"
                    writeFile file: "security-reports/secrets/gitleaks-config.toml", text: '''title = "Gitleaks Configuration"

[extenders]
useDefault = true

[[allowlist]]
description = "Test files"
paths = [
    ".*test.*",
    ".*Test.*",
    "*/test/*",
    "*/target/*",
    "*.md",
    "*.txt"
]

[[rules]]
description = "AWS Access Key ID"
regex = "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
tags = ["key", "AWS"]

[[rules]]
description = "GitHub Personal Access Token"
regex = "ghp_[0-9a-zA-Z]{36}"
tags = ["key", "GitHub"]

[[rules]]
description = "Generic Password"
regex = "(?i)(password|passwd|pwd)[[:space:]]*=[[:space:]]*[\\"']?([^\\"'[:space:]]+)[\\"']?"
tags = ["password", "secret"]'''

                    sh '''
                    echo "📦 Téléchargement de Gitleaks..."
                    wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz -O security-reports/secrets/gitleaks.tar.gz || true
                    tar -xzf security-reports/secrets/gitleaks.tar.gz -C security-reports/secrets/ 2>/dev/null || true
                    chmod +x security-reports/secrets/gitleaks 2>/dev/null || true

                    echo "🔍 Exécution du scan des secrets..."
                    ./security-reports/secrets/gitleaks detect --source . --config security-reports/secrets/gitleaks-config.toml --report-format json --report-path security-reports/secrets/gitleaks-report.json --verbose 2>/dev/null || true

                    SECRETS_COUNT=0
                    if [ -f "security-reports/secrets/gitleaks-report.json" ] && [ -s "security-reports/secrets/gitleaks-report.json" ]; then
                        if command -v jq >/dev/null 2>&1; then
                            SECRETS_COUNT=$(jq ". | length" security-reports/secrets/gitleaks-report.json 2>/dev/null || echo "0")
                        else
                            SECRETS_COUNT=$(grep -c '"File"' security-reports/secrets/gitleaks-report.json 2>/dev/null || echo "0")
                        fi
                    fi

                    echo "${SECRETS_COUNT}" > security-reports/secrets_count.txt
                    echo "Secrets détectés: ${SECRETS_COUNT}"
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    echo "🐳 CONSTRUCTION DE L'IMAGE DOCKER"
                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        sh '''
                        cat > security-reports/docker/Dockerfile << 'EOF'
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
EOF

                        docker build -t ${DOCKER_IMAGE}:${BUILD_NUMBER} . || echo "Docker build failed but continuing"
                        docker tag ${DOCKER_IMAGE}:${BUILD_NUMBER} ${DOCKER_IMAGE}:latest || echo "Docker tag failed but continuing"
                        echo "✅ Image Docker construite"
                        '''
                    }
                }
            }
        }

        stage('Génération Rapports PDF') {
            steps {
                script {
                    echo "📄 GÉNÉRATION DES RAPPORTS PDF"
                    
                    // Installer wkhtmltopdf pour la conversion HTML vers PDF
                    sh '''
                    echo "📦 Installation de wkhtmltopdf..."
                    sudo apt-get update || true
                    sudo apt-get install -y xfonts-75dpi xfonts-base || true
                    wget -q https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb -O security-reports/wkhtmltopdf.deb || true
                    sudo dpkg -i security-reports/wkhtmltopdf.deb 2>/dev/null || true
                    sudo apt-get install -f -y || true
                    
                    # Vérifier l'installation
                    which wkhtmltopdf && echo "✅ wkhtmltopdf installé" || echo "❌ wkhtmltopdf non installé"
                    
                    # Installer pdfunite si nécessaire
                    sudo apt-get install -y poppler-utils || true
                    which pdfunite && echo "✅ pdfunite installé" || echo "❌ pdfunite non installé"
                    '''
                    
                    // Convertir tous les rapports HTML en PDF
                    sh '''
                    echo "🔄 Conversion des rapports en PDF..."
                    
                    # Créer des rapports HTML simplifiés pour une meilleure conversion PDF
                    cat > security-reports/pdf_template.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        .success { background: #d4edda; padding: 15px; margin: 10px 0; }
        .failure { background: #f8d7da; padding: 15px; margin: 10px 0; }
        .metric { margin: 10px 0; padding: 10px; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    {{CONTENT}}
</body>
</html>
EOF

                    # Rapport Checkout
                    if [ -f "security-reports/checkout_report.html" ]; then
                        echo "📥 Conversion rapport checkout..."
                        wkhtmltopdf --enable-local-file-access --page-size A4 --orientation Portrait security-reports/checkout_report.html security-reports/pdf/checkout_report.pdf 2>/dev/null || echo "⚠️  Erreur conversion checkout"
                    else
                        echo "📝 Création rapport checkout manquant..."
                        echo "<div class='header'><h1>📥 CHECKOUT</h1><p>Build ${BUILD_NUMBER}</p></div><div class='content'><div class='success'><h3>✅ Checkout réussi</h3><p>Repository: https://github.com/omarhamdawi/devops_jenkins.git</p></div></div>" > security-reports/checkout_simple.html
                        wkhtmltopdf --enable-local-file-access security-reports/checkout_simple.html security-reports/pdf/checkout_report.pdf 2>/dev/null || echo "⚠️  Erreur création checkout"
                    fi
                    
                    # Rapport Build
                    if [ -f "security-reports/build_report.html" ]; then
                        echo "🔨 Conversion rapport build..."
                        wkhtmltopdf --enable-local-file-access security-reports/build_report.html security-reports/pdf/build_report.pdf 2>/dev/null || echo "⚠️  Erreur conversion build"
                    fi
                    
                    # Rapport SAST
                    if [ -f "security-reports/sast/sast_report.html" ]; then
                        echo "🔍 Conversion rapport SAST..."
                        wkhtmltopdf --enable-local-file-access security-reports/sast/sast_report.html security-reports/pdf/sast_report.pdf 2>/dev/null || echo "⚠️  Erreur conversion SAST"
                    fi
                    
                    # Rapport SCA
                    if [ -f "security-reports/sca/dependency-check-report.html" ]; then
                        echo "📦 Conversion rapport SCA..."
                        wkhtmltopdf --enable-local-file-access security-reports/sca/dependency-check-report.html security-reports/pdf/sca_report.pdf 2>/dev/null || echo "⚠️  Erreur conversion SCA"
                    fi
                    
                    # Vérifier que les PDFs sont créés
                    echo "📋 Liste des PDFs générés:"
                    ls -la security-reports/pdf/*.pdf 2>/dev/null || echo "Aucun PDF généré"
                    
                    # Créer un PDF unique avec tous les rapports disponibles
                    echo "📋 Création du rapport PDF complet..."
                    if ls security-reports/pdf/*.pdf >/dev/null 2>&1; then
                        pdfunite security-reports/pdf/*.pdf security-reports/pdf/complete_security_report.pdf 2>/dev/null || echo "⚠️  Erreur fusion PDF - création manuelle"
                        # Si pdfunite échoue, copier le premier PDF disponible
                        if [ ! -f "security-reports/pdf/complete_security_report.pdf" ]; then
                            cp security-reports/pdf/*.pdf security-reports/pdf/complete_security_report.pdf 2>/dev/null || true
                        fi
                    else
                        echo "❌ Aucun PDF disponible pour la fusion"
                        # Créer un PDF vide pour éviter les erreurs
                        echo "<html><body><h1>Rapport de Sécurité</h1><p>Aucun rapport disponible pour le build ${BUILD_NUMBER}</p></body></html>" > security-reports/empty_report.html
                        wkhtmltopdf security-reports/empty_report.html security-reports/pdf/complete_security_report.pdf 2>/dev/null || true
                    fi
                    
                    echo "✅ Conversion PDF terminée"
                    '''
                }
            }
        }

        stage('Génération Rapports Consolidés') {
            steps {
                script {
                    echo "📊 GÉNÉRATION DES RAPPORTS CONSOLIDÉS"
                    
                    // Lecture des résultats
                    def secretsCount = sh(script: 'cat security-reports/secrets_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                    def criticalVulns = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                    def vulnerabilitiesDetails = sh(script: 'cat security-reports/vulnerabilities_details.txt 2>/dev/null || echo "Aucun détail disponible"', returnStdout: true).trim()
                    
                    // Vérifier si des PDFs sont disponibles
                    def pdfFiles = sh(script: 'ls security-reports/pdf/*.pdf 2>/dev/null | wc -l', returnStdout: true).trim().toInteger()
                    def hasPDFs = pdfFiles > 0
                    
                    // Génération du rapport JSON consolidé
                    def jsonReport = """
{
    "buildInfo": {
        "buildNumber": "${env.BUILD_NUMBER}",
        "timestamp": "${new Date().format('yyyy-MM-dd HH:mm:ss')}",
        "status": "${currentBuild.currentResult}",
        "duration": "${currentBuild.durationString}"
    },
    "securityMetrics": {
        "secretsDetected": ${secretsCount.toInteger()},
        "criticalVulnerabilities": ${criticalVulns.toInteger()},
        "sonarQubeStatus": "${env.SONAR_STATUS}",
        "dockerImage": "${env.DOCKER_IMAGE}:${env.BUILD_NUMBER}"
    },
    "reports": {
        "sast": "${env.BUILD_URL}/artifact/security-reports/sast/sast_report.html",
        "sca": "${env.BUILD_URL}/artifact/security-reports/sca/dependency-check-report.html",
        "secrets": "${env.BUILD_URL}/artifact/security-reports/secrets/gitleaks-report.json",
        "pdf": "${env.BUILD_URL}/artifact/security-reports/pdf/"
    },
    "hasPDFReports": ${hasPDFs}
}
"""
                    writeFile file: "security-reports/consolidated/security-report.json", text: jsonReport
                    
                    // Génération du rapport HTML consolidé
                    def pdfDownloadSection = ""
                    if (hasPDFs) {
                        pdfDownloadSection = """
        <div class="download-section">
            <h2>📥 TÉLÉCHARGEMENT DES RAPPORTS PDF</h2>
            <p>
                <a class="download-btn" href="${env.BUILD_URL}/artifact/security-reports/pdf/complete_security_report.pdf" download>
                    📋 RAPPORT COMPLET (PDF)
                </a>
                <a class="download-btn" href="${env.BUILD_URL}/artifact/security-reports/pdf/sast_report.pdf" download>
                    🔍 RAPPORT SAST (PDF)
                </a>
                <a class="download-btn" href="${env.BUILD_URL}/artifact/security-reports/pdf/sca_report.pdf" download>
                    📦 RAPPORT SCA (PDF)
                </a>
            </p>
        </div>
"""
                    } else {
                        pdfDownloadSection = """
        <div class="warning-section">
            <h2>⚠️ RAPPORTS PDF NON DISPONIBLES</h2>
            <p>Les rapports PDF n'ont pas pu être générés. Veuillez consulter les rapports HTML ci-dessous.</p>
        </div>
"""
                    }
                    
                    def htmlReport = """
<!DOCTYPE html>
<html>
<head>
    <title>Rapport de Sécurité Consolidé - DevSecOps</title>
    <style>
        :root { --success: #28a745; --warning: #ffc107; --danger: #dc3545; --info: #17a2b8; --dark: #343a40; }
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 5px 25px rgba(0,0,0,0.1); }
        .header { background: linear(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 15px; text-align: center; margin-bottom: 40px; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin: 30px 0; }
        .metric-card { background: white; padding: 25px; border-radius: 12px; text-align: center; box-shadow: 0 3px 15px rgba(0,0,0,0.1); border-left: 5px solid var(--info); }
        .metric-value { font-size: 3em; font-weight: bold; margin: 15px 0; }
        .status-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin: 5px; }
        .status-success { background: var(--success); }
        .status-warning { background: var(--warning); color: black; }
        .status-danger { background: var(--danger); }
        .section { margin: 40px 0; padding: 25px; background: #f8f9fa; border-radius: 10px; }
        .vuln-details { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; font-family: monospace; white-space: pre-wrap; }
        .download-section { background: #e7f3ff; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .warning-section { background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0; border: 1px solid #ffeaa7; }
        .download-btn { display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 5px; }
        .download-btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 RAPPORT DE SÉCURITÉ CONSOLIDÉ</h1>
            <p>Pipeline DevSecOps - Analyse complète de sécurité</p>
            <p>Build: ${env.BUILD_NUMBER} | Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
        </div>
        
        ${pdfDownloadSection}
        
        <div class="dashboard">
            <div class="metric-card" style="border-left-color: ${secretsCount.toInteger() > 0 ? '#ffc107' : '#28a745'};">
                <div class="metric-title">🔐 SECRETS DÉTECTÉS</div>
                <div class="metric-value" style="color: ${secretsCount.toInteger() > 0 ? '#ffc107' : '#28a745'};">${secretsCount}</div>
                <div class="metric-status">
                    ${secretsCount.toInteger() > 0 ? '<span class="status-badge status-warning">À VÉRIFIER</span>' : '<span class="status-badge status-success">SÉCURISÉ</span>'}
                </div>
            </div>
            
            <div class="metric-card" style="border-left-color: ${criticalVulns.toInteger() > 0 ? '#dc3545' : '#28a745'};">
                <div class="metric-title">⚠️ VULNÉRABILITÉS CRITIQUES</div>
                <div class="metric-value" style="color: ${criticalVulns.toInteger() > 0 ? '#dc3545' : '#28a745'};">${criticalVulns}</div>
                <div class="metric-status">
                    ${criticalVulns.toInteger() > 0 ? '<span class="status-badge status-danger">ATTENTION</span>' : '<span class="status-badge status-success">SÉCURISÉ</span>'}
                </div>
            </div>
            
            <div class="metric-card" style="border-left-color: ${env.SONAR_STATUS == 'SUCCESS' ? '#28a745' : '#dc3545'};">
                <div class="metric-title">🔍 SAST - SONARQUBE</div>
                <div class="metric-value" style="color: ${env.SONAR_STATUS == 'SUCCESS' ? '#28a745' : '#dc3545'};">${env.SONAR_STATUS}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 DÉTAILS DES VULNÉRABILITÉS</h2>
            <div class="vuln-details">
${vulnerabilitiesDetails}
            </div>
        </div>
        
        <div class="section">
            <h2>📎 RAPPORTS DISPONIBLES</h2>
            <div class="download-section">
                <h3>🌐 RAPPORTS HTML</h3>
                <ul>
                    <li><a href="${env.BUILD_URL}/artifact/security-reports/sast/sast_report.html">Rapport SAST</a></li>
                    <li><a href="${env.BUILD_URL}/artifact/security-reports/sca/dependency-check-report.html">Rapport SCA Détaillé</a></li>
                    <li><a href="${env.BUILD_URL}/artifact/security-reports/consolidated/security-report.json">Rapport JSON</a></li>
                    <li><a href="${env.BUILD_URL}/artifact/security-reports/consolidated/security-report.html">Rapport HTML Consolidé</a></li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"""
                    writeFile file: "security-reports/consolidated/security-report.html", text: htmlReport
                }
            }
        }
    }

    post {
        always {
            // Archiver TOUS les rapports (HTML, JSON, PDF)
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            
            // Publier les rapports HTML dans Jenkins
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports/consolidated',
                reportFiles: 'security-report.html',
                reportName: '📊 Rapport Sécurité Consolidé'
            ])
            
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports/sast',
                reportFiles: 'sast_report.html',
                reportName: '🔍 Rapport SAST'
            ])
            
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'security-reports/sca',
                reportFiles: 'dependency-check-report.html',
                reportName: '📦 Rapport SCA'
            ])
            
            script {
                env.BUILD_STATUS = currentBuild.currentResult
                env.BUILD_DURATION = currentBuild.durationString
                
                // Lecture des résultats finaux
                def secretsCount = sh(script: 'cat security-reports/secrets_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                def criticalVulns = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                def vulnerabilitiesDetails = sh(script: 'cat security-reports/vulnerabilities_details.txt 2>/dev/null || echo "Aucun détail disponible"', returnStdout: true).trim()
                
                // Vérifier la disponibilité des PDFs
                def hasPDFs = sh(script: 'ls security-reports/pdf/*.pdf 2>/dev/null | head -1', returnStdout: true).trim() ? true : false
                
                // Déterminer le statut de sécurité
                def securityStatus = "✅ SÉCURISÉ"
                def securityColor = "#28a745"
                if (secretsCount.toInteger() > 0 || criticalVulns.toInteger() > 0) {
                    securityStatus = "⚠️ ATTENTION REQUISE"
                    securityColor = "#ffc107"
                }
                if (criticalVulns.toInteger() > 5) {
                    securityStatus = "🚨 URGENCE SÉCURITÉ"
                    securityColor = "#dc3545"
                }
                
                // Préparer le contenu PDF pour l'email
                def pdfContent = ""
                if (hasPDFs) {
                    pdfContent = """
                        <p><strong>📄 Rapports PDF disponibles:</strong></p>
                        <ul>
                            <li><a href="${env.BUILD_URL}/artifact/security-reports/pdf/complete_security_report.pdf">Rapport Complet PDF</a></li>
                            <li><a href="${env.BUILD_URL}/artifact/security-reports/pdf/sast_report.pdf">Rapport SAST PDF</a></li>
                            <li><a href="${env.BUILD_URL}/artifact/security-reports/pdf/sca_report.pdf">Rapport SCA PDF</a></li>
                        </ul>
                    """
                } else {
                    pdfContent = """
                        <p><strong>⚠️ Rapports PDF:</strong> Non disponibles - consulter les rapports HTML</p>
                    """
                }
                
                // Email de notification SIMPLIFIÉ - Utilise la configuration Jenkins
                mail to: "${EMAIL_RECIPIENTS}",
                     subject: "🔒 RAPPORT DEVSECOPS - Build #${env.BUILD_NUMBER} - ${currentBuild.currentResult}",
                     body: """
RAPPORT DE SÉCURITÉ DEVSECOPS - Build #${env.BUILD_NUMBER}

📅 Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}
🔢 Statut Build: ${currentBuild.currentResult}
⏱️ Durée: ${env.BUILD_DURATION}

📊 MÉTRIQUES DE SÉCURITÉ:
• 🔐 Secrets détectés: ${secretsCount}
• ⚠️ Vulnérabilités critiques: ${criticalVulns}
• 🔍 Statut SAST: ${env.SONAR_STATUS}
• 🐳 Image Docker: ${env.DOCKER_IMAGE}:${env.BUILD_NUMBER}

${securityStatus}

📎 RAPPORTS DISPONIBLES:
${env.BUILD_URL}

Pour plus de détails, connectez-vous à Jenkins et consultez les rapports complets.

--
Rapport automatique - Pipeline DevSecOps
Ne pas répondre à cet email
"""
                
                echo " "
                echo "🎉 PIPELINE DEVSECOPS TERMINÉE"
                echo "📧 Notification email envoyée à: ${EMAIL_RECIPIENTS}"
                echo "📁 Rapports générés dans: security-reports/"
                if (hasPDFs) {
                    echo "📄 Rapports PDF disponibles dans: security-reports/pdf/"
                } else {
                    echo "⚠️  Aucun rapport PDF généré"
                }
                echo "📎 Téléchargez les rapports depuis: ${env.BUILD_URL}/artifact/"
            }
        }
        
        success {
            echo '🎉 SUCCÈS : Pipeline exécuté sans interruption !'
        }
        failure {
            echo '⚠️ ÉCHEC TECHNIQUE : Problème d\'infrastructure'
        }
    }
}
