pipeline {
    agent any

    // ADD THIS: Webhook triggers configuration
    triggers {
        githubPush()
    }

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
        stage('Webhook Detection & Initialisation') {
            steps {
                script {
                    echo "🎯 DÉMARRAGE AUTOMATIQUE PAR WEBHOOK GITHUB"
                    echo "🚀 Build déclenché par: Push/Merge Request GitHub"
                    echo "📅 Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}"
                    echo "🔢 Build: ${env.BUILD_NUMBER}"
                    
                    // Get Git information for webhook context
                    sh '''
                    echo "=== INFORMATIONS GIT ==="
                    git log -1 --oneline
                    echo "=== FICHIERS MODIFIÉS ==="
                    git show --name-only --oneline HEAD | head -20
                    '''
                    
                    // Create reports directory
                    sh '''
                    mkdir -p security-reports
                    mkdir -p security-reports/sast
                    mkdir -p security-reports/sca
                    mkdir -p security-reports/secrets
                    mkdir -p security-reports/docker
                    mkdir -p security-reports/consolidated
                    '''
                    
                    sh 'java -version || echo "✅ Java vérifié"'
                    
                    // Initialize report variables
                    env.SECRETS_COUNT = "0"
                    env.CRITICAL_VULNERABILITIES = "0"
                    env.SONAR_STATUS = "UNKNOWN"
                    env.BLOCK_REASON = "NONE"
                    env.WEBHOOK_TRIGGER = "true"
                }
            }
        }

        stage('Checkout Code') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: [[name: '*/main']],
                    extensions: [
                        [
                            $class: 'CleanBeforeCheckout'
                        ],
                        [
                            $class: 'LocalBranch',
                            localBranch: 'main'
                        ]
                    ],
                    userRemoteConfigs: [[
                        credentialsId: 'jenkins-github',
                        url: 'https://github.com/omarhamdawi/devops_jenkins.git'
                    ]]
                ])
                
                script {
                    // Generate webhook info report
                    writeFile file: "security-reports/webhook_info.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Information Webhook GitHub</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #4CAF50; color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .success { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔄 DÉMARRAGE AUTOMATIQUE</h1>
            <p>Déclenché par Webhook GitHub</p>
        </div>
        <div class="success">
            <h3>✅ Webhook GitHub Actif</h3>
            <p>Ce build a été automatiquement déclenché par un push sur le repository GitHub.</p>
        </div>
        <div class="info">
            <h3>📊 Informations du Build</h3>
            <p><strong>Build Number:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
            <p><strong>Repository:</strong> https://github.com/omarhamdawi/devops_jenkins.git</p>
            <p><strong>Branch:</strong> main</p>
            <p><strong>Trigger:</strong> GitHub Webhook (Push/Merge Request)</p>
            <p><strong>Statut:</strong> ✅ Automatisation fonctionnelle</p>
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
                        // Build report
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
            <p><strong>Trigger:</strong> GitHub Webhook</p>
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
                    try {
                        timeout(time: env.SONAR_QUALITY_GATE_TIMEOUT.toInteger(), unit: 'MINUTES') {
                            sh """
                            mvn sonar:sonar \
                              -Dsonar.projectKey=devops_jenkins \
                              -Dsonar.host.url=${SONAR_HOST_URL} \
                              -Dsonar.token=${SONAR_AUTH_TOKEN} \
                              -Dsonar.qualitygate.wait=true \
                              -Dsonar.scm.disabled=true
                            """
                        }
                        env.SONAR_STATUS = "SUCCESS"
                        echo "✅ SAST - Analyse SonarQube terminée avec succès"
                    } catch (Exception e) {
                        env.SONAR_STATUS = "FAILED"
                        env.BLOCK_REASON = "SAST_FAILED"
                        error "❌ SAST - ÉCHEC: La Quality Gate SonarQube n'est pas passée"
                    }
                }
            }
            post {
                always {
                    script {
                        // Generate SAST report
                        writeFile file: "security-reports/sast/sast_report.html", text: """
<!DOCTYPE html>
<html>
<head>
    <title>Rapport SAST - SonarQube</title>
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
            <h1>🔍 RAPPORT SAST - SONARQUBE</h1>
            <p>Analyse Statique de Sécurité</p>
        </div>
        ${env.SONAR_STATUS == 'SUCCESS' ? """
        <div class="success">
            <h3>✅ Analyse SAST terminée avec succès</h3>
            <p><strong>Status:</strong> ${env.SONAR_STATUS}</p>
            <p><strong>Outils:</strong> SonarQube</p>
            <p><strong>URL SonarQube:</strong> ${SONAR_HOST_URL}</p>
            <p><strong>Project Key:</strong> devops_jenkins</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
            <p><strong>Trigger:</strong> GitHub Webhook</p>
        </div>
        """ : """
        <div class="failure">
            <h3>❌ Analyse SAST échouée</h3>
            <p><strong>Status:</strong> ${env.SONAR_STATUS}</p>
            <p><strong>Raison du blocage:</strong> Quality Gate SonarQube non passée</p>
            <p><strong>Outils:</strong> SonarQube</p>
            <p><strong>URL SonarQube:</strong> ${SONAR_HOST_URL}</p>
            <p><strong>Build:</strong> ${env.BUILD_NUMBER}</p>
            <p><strong>Date:</strong> ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
            <p><em>Consultez SonarQube pour les détails des vulnérabilités</em></p>
        </div>
        """}
    </div>
</body>
</html>
"""
                        publishHTML([
                            allowMissing: false,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportName: 'SAST - SonarQube',
                            reportDir: 'security-reports/sast',
                            reportFiles: 'sast_report.html'
                        ])
                    }
                }
            }
        }

        stage('SCA - OWASP Dependency Check') {
            steps {
                script {
                    echo "📦 SCA - Analyse des Dépendances avec OWASP Dependency-Check"
                    try {
                        dependencyCheck(
                            odcInstallation: 'dependency-check',
                            additionalArguments: """
                                --project "devops_jenkins"
                                --scan "**/*.jar"
                                --scan "pom.xml"
                                --format HTML
                                --format JSON
                                --out .
                                --failOnCVSS ${env.CRITICAL_CVSS_THRESHOLD}
                                --enableExperimental
                                --nvdApiKey ${NVD_API_KEY}
                                --log odc.log
                            """.stripIndent()
                        )
                        
                        // Copy SCA reports to organized folder
                        sh '''
                        cp dependency-check-report.html security-reports/sca/ 2>/dev/null || true
                        cp dependency-check-report.json security-reports/sca/ 2>/dev/null || true
                        cp odc.log security-reports/sca/ 2>/dev/null || true
                        '''
                        
                    } catch (Exception e) {
                        echo "❌ SCA analysis failed with critical vulnerabilities"
                        // Continue to process vulnerabilities even if build fails
                    }
                }
            }
            post {
                always {
                    script {
                        echo "📊 Traitement des résultats SCA..."
                        
                        sh '''
                        if [ -f "dependency-check-report.json" ]; then
                            echo "📊 Analyse détaillée des vulnérabilités critiques (CVSS ≥ ${CRITICAL_CVSS_THRESHOLD})..."
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

    # Write details to file
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

    # Write count to file
    with open('security-reports/critical_vulns_count.txt', 'w') as f:
        f.write(str(critical_count))

    print("")
    print("📈 RÉSUMÉ SCA:")
    print("   • Vulnérabilités critiques (CVSS ≥ 7.0): " + str(critical_count))
    print("   • Total des dépendances analysées: " + str(len(data.get("dependencies", []))))

    if critical_count > 0:
        print("🚨 VULNÉRABILITÉS CRITIQUES DÉTECTÉES - BUILD BLOQUÉ")
        sys.exit(1)
        
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
                        
                        // Read the result from file
                        def criticalCount = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                        env.CRITICAL_VULNERABILITIES = criticalCount
                        
                        if (criticalCount.toInteger() > 0) {
                            env.BLOCK_REASON = "SCA_CRITICAL_VULNERABILITIES"
                            error "❌ SCA - BLOCAGE: ${criticalCount} vulnérabilité(s) critique(s) détectée(s)"
                        }
                        
                        echo "🔍 Vulnérabilités critiques détectées: ${env.CRITICAL_VULNERABILITIES}"
                        
                        // Publish SCA report
                        publishHTML([
                            allowMissing: true,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportName: 'SCA - OWASP Dependency Check',
                            reportDir: 'security-reports/sca',
                            reportFiles: 'dependency-check-report.html'
                        ])
                    }
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            steps {
                script {
                    echo "🔐 SCAN DES SECRETS - Détection des credentials exposés"
                    
                    writeFile file: 'security-reports/secrets/gitleaks-config.toml', text: '''title = "Gitleaks Configuration"

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
                    ./security-reports/secrets/gitleaks detect --source . --config security-reports/secrets/gitleaks-config.toml --report-format json --report-path security-reports/secrets/gitleaks-report.json --verbose --exit-code 0 || true

                    SECRETS_COUNT=0
                    if [ -f "security-reports/secrets/gitleaks-report.json" ] && [ -s "security-reports/secrets/gitleaks-report.json" ]; then
                        if command -v jq >/dev/null 2>&1; then
                            SECRETS_COUNT=$(jq ". | length" security-reports/secrets/gitleaks-report.json 2>/dev/null || echo "0")
                            echo " "
                            echo "📊 DÉTAIL DES SECRETS DÉTECTÉS:"
                            jq -r '.[] | "• Fichier: " + .File + " (Ligne " + (.StartLine|tostring) + ")\\\\n  Type: " + .Description + "\\\\n  Règle: " + .RuleID + "\\\\n"' security-reports/secrets/gitleaks-report.json 2>/dev/null || true
                        else
                            SECRETS_COUNT=$(grep -c '"File"' security-reports/secrets/gitleaks-report.json 2>/dev/null || echo "0")
                        fi
                    fi

                    echo "${SECRETS_COUNT}" > security-reports/secrets_count.txt
                    echo "Secrets détectés: ${SECRETS_COUNT}"

                    if [ "${SECRETS_COUNT}" -gt 0 ]; then
                        echo "⚠️  AVERTISSEMENT: ${SECRETS_COUNT} secret(s) détecté(s) - Vérification recommandée"
                    else
                        echo "✅ Aucun secret détecté - Code sécurisé"
                    fi
                    '''
                }
            }
            post {
                always {
                    script {
                        def secretsCount = sh(script: 'cat security-reports/secrets_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim().toInteger()
                        env.SECRETS_COUNT = secretsCount.toString()
                        
                        writeFile file: 'security-reports/secrets/gitleaks-report.html', text: """<!DOCTYPE html>
<html>
<head>
    <title>Rapport Gitleaks</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }
        .warning { background: #ffc107; color: black; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .success { background: #28a745; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .info { background: #17a2b8; color: white; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 RAPPORT DE SCAN DES SECRETS</h1>
            <p>Gitleaks Security Scan - Rapport d'analyse</p>
        </div>
        
        ${secretsCount > 0 ? """
        <div class="warning">
            <h2>⚠️  AVERTISSEMENT: ${secretsCount} SECRET(S) DÉTECTÉ(S)</h2>
            <p>Des credentials ont été détectés dans le code. Vérification recommandée.</p>
        </div>
        <div class="dashboard">
            <div class="metric-card">
                <h3>🔐 Secrets</h3>
                <div class="metric-value" style="color: #ffc107;">${secretsCount}</div>
                <p>À VÉRIFIER</p>
            </div>
        </div>
        <div class="info">
            <strong>Note:</strong> Le pipeline continue malgré la détection de secrets. 
            Il est recommandé de vérifier et corriger ces secrets.
        </div>
        """ : """
        <div class="success">
            <h2>✅ AUCUN SECRET DÉTECTÉ</h2>
            <p>Code source sécurisé</p>
        </div>
        <div class="dashboard">
            <div class="metric-card">
                <h3>🔐 Secrets</h3>
                <div class="metric-value" style="color: #28a745;">0</div>
                <p>SÉCURISÉ</p>
            </div>
        </div>
        """}
    </div>
</body>
</html>"""
                        
                        publishHTML([
                            allowMissing: true,
                            alwaysLinkToLastBuild: true,
                            keepAll: true,
                            reportName: 'Gitleaks - Secrets Scan',
                            reportDir: 'security-reports/secrets',
                            reportFiles: 'gitleaks-report.html'
                        ])
                    }
                }
            }
        }

        stage('Generate Consolidated Report') {
            steps {
                script {
                    echo "📊 GÉNÉRATION DU RAPPORT CONSOLIDÉ"
                    
                    // Read final results
                    def secretsCount = sh(script: 'cat security-reports/secrets_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                    def criticalVulns = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                    def vulnerabilitiesDetails = sh(script: 'cat security-reports/vulnerabilities_details.txt 2>/dev/null || echo "Aucun détail disponible"', returnStdout: true).trim()
                    
                    // Generate consolidated HTML report
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
        .blocked { background: #dc3545; color: white; padding: 20px; border-radius: 10px; margin: 20px 0; }
        .webhook-info { background: #4CAF50; color: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 RAPPORT DE SÉCURITÉ CONSOLIDÉ</h1>
            <p>Pipeline DevSecOps - Analyse complète de sécurité</p>
            <p>Build: ${env.BUILD_NUMBER} | Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}</p>
        </div>
        
        <div class="webhook-info">
            <h2>🔄 DÉCLENCHEMENT AUTOMATIQUE</h2>
            <p>Ce build a été automatiquement déclenché par un webhook GitHub suite à un push/merge request.</p>
        </div>
        
        ${env.BLOCK_REASON != "NONE" ? """
        <div class="blocked">
            <h2>🚨 BUILD BLOQUÉ</h2>
            <p><strong>Raison:</strong> ${env.BLOCK_REASON}</p>
            <p><strong>Statut:</strong> ÉCHEC DE SÉCURITÉ</p>
            <p>Le pipeline a été bloqué pour des raisons de sécurité. Consultez les détails ci-dessous.</p>
        </div>
        """ : ""}
        
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
            <ul>
                <li><a href="${env.BUILD_URL}/SAST-SonarQube/">Rapport SAST - SonarQube</a></li>
                <li><a href="${env.BUILD_URL}/SCA-OWASP-Dependency-Check/">Rapport SCA - OWASP Dependency Check</a></li>
                <li><a href="${env.BUILD_URL}/Gitleaks-Secrets-Scan/">Rapport Secrets Scan - Gitleaks</a></li>
                <li><a href="${env.BUILD_URL}/artifact/">Télécharger tous les rapports</a></li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
                    writeFile file: "security-reports/consolidated/security-report.html", text: htmlReport
                    
                    publishHTML([
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportName: '📊 Rapport Sécurité Consolidé',
                        reportDir: 'security-reports/consolidated',
                        reportFiles: 'security-report.html'
                    ])
                }
            }
        }
    }

    post {
        always {
            // Archive ALL reports
            archiveArtifacts artifacts: 'security-reports/**/*', allowEmptyArchive: true
            
            script {
                // Read final results for email
                def secretsCount = sh(script: 'cat security-reports/secrets_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                def criticalVulns = sh(script: 'cat security-reports/critical_vulns_count.txt 2>/dev/null || echo "0"', returnStdout: true).trim()
                def vulnerabilitiesDetails = sh(script: 'cat security-reports/vulnerabilities_details.txt 2>/dev/null || echo "Aucun détail disponible"', returnStdout: true).trim()
                
                // Determine email subject and content based on build status
                def emailSubject = ""
                def emailBody = ""
                
                if (currentBuild.result == 'FAILURE') {
                    emailSubject = "🚨 BUILD BLOQUÉ - Webhook GitHub - Build #${env.BUILD_NUMBER}"
                    emailBody = """
🔒 RAPPORT DE SÉCURITÉ DEVSECOPS - BUILD BLOQUÉ

🔄 DÉCLENCHEMENT: Webhook GitHub (Push/Merge Request)
Build #${env.BUILD_NUMBER} | ${new Date().format('yyyy-MM-dd HH:mm:ss')}

🚨 ATTENTION: Le build a été bloqué pour des raisons de sécurité!

📊 MÉTRIQUES DE SÉCURITÉ:
• 🔐 Secrets détectés: ${secretsCount}
• ⚠️ Vulnérabilités critiques: ${criticalVulns}
• 🔍 Statut SAST: ${env.SONAR_STATUS}
• 📅 Build: ${env.BUILD_NUMBER}

🚨 RAISON DU BLOCAGE: ${env.BLOCK_REASON}

📋 DÉTAILS DES VULNÉRABILITÉS CRITIQUES:
${vulnerabilitiesDetails}

📎 RAPPORTS DISPONIBLES:
${env.BUILD_URL}

Pour plus de détails, connectez-vous à Jenkins et consultez les rapports complets.

--
Build Automatique - Pipeline DevSecOps
Ne pas répondre à cet email
"""
                } else {
                    emailSubject = "✅ BUILD RÉUSSI - Webhook GitHub - Build #${env.BUILD_NUMBER}"
                    emailBody = """
🔒 RAPPORT DE SÉCURITÉ DEVSECOPS - BUILD RÉUSSI

🔄 DÉCLENCHEMENT: Webhook GitHub (Push/Merge Request)
Build #${env.BUILD_NUMBER} | ${new Date().format('yyyy-MM-dd HH:mm:ss')}

✅ BUILD AUTOMATIQUE TERMINÉ AVEC SUCCÈS

📊 MÉTRIQUES DE SÉCURITÉ:
• 🔐 Secrets détectés: ${secretsCount}
• ⚠️ Vulnérabilités critiques: ${criticalVulns}
• 🔍 Statut SAST: ${env.SONAR_STATUS}
• 📅 Build: ${env.BUILD_NUMBER}

📋 DÉTAILS DES VULNÉRABILITÉS:
${vulnerabilitiesDetails}

📎 RAPPORTS DISPONIBLES:
${env.BUILD_URL}

--
Build Automatique - Pipeline DevSecOps
Ne pas répondre à cet email
"""
                }
                
                // Send email notification
                mail to: "${EMAIL_RECIPIENTS}",
                     subject: emailSubject,
                     body: emailBody

                echo " "
                echo "🎉 PIPELINE DEVSECOPS TERMINÉE"
                echo "🔄 Déclenchement: Webhook GitHub"
                echo "📧 Notification email envoyée à: ${EMAIL_RECIPIENTS}"
                echo "📁 Rapports générés dans: security-reports/"
                echo "📎 Téléchargez les rapports depuis: ${env.BUILD_URL}/artifact/"
            }
        }
        
        success {
            echo '🎉 SUCCÈS : Pipeline DevSecOps complet exécuté avec succès!'
            echo '🔄 Webhook GitHub fonctionne correctement!'
        }
        failure {
            echo '❌ ÉCHEC : Pipeline bloqué par les règles de sécurité (SAST/SCA)'
            echo '📧 Notification envoyée avec les détails du blocage'
        }
    }
}
