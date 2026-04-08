#!/usr/bin/env python3
"""
Quick Start Guide for CNS - Cybersecurity Network System
Enhanced Network Security through Custom Snort Rules for Zero-Day Attack Detection

This script provides interactive guidance for running the system.
"""

import sys
import os
from pathlib import Path


def print_header(text):
    """Print a formatted header."""
    print("\n" + "=" * 50)
    print(f"  {text}")
    print("=" * 50 + "\n")


def print_section(text):
    """Print a section header."""
    print(f"\n▶ {text}")
    print("-" * 50)


def check_dependencies():
    """Check if required Python packages are installed."""
    print_section("Checking Dependencies")
    
    required_packages = {
        'pandas': 'pandas',
        'numpy': 'numpy',
        'scikit-learn': 'sklearn',
        'joblib': 'joblib',
        'pyyaml': 'yaml',
        'watchdog': 'watchdog'
    }
    missing = []
    
    for pip_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"  ✓ {pip_name}")
        except ImportError:
            print(f"  ✗ {pip_name} (MISSING)")
            missing.append(pip_name)
    
    if missing:
        print(f"\n❌ Missing packages: {', '.join(missing)}")
        print("\nInstall with:")
        print("  pip install -r requirements.txt\n")
        return False
    else:
        print("\n✓ All dependencies installed!\n")
        return True


def check_files():
    """Check if all required project files exist."""
    print_section("Checking Project Files")
    
    files = {
        "config/config.yaml": "Configuration file",
        "src/demo.py": "Demo script",
        "src/data_loader.py": "Data loader module",
        "src/feature_engineering.py": "Feature engineering module",
        "src/model.py": "ML model module",
        "src/train.py": "Training script",
        "src/detect.py": "Detection script",
        "src/monitor.py": "Real-time monitor",
        "src/rule_generator.py": "Rule generation module",
        "local.rules": "Snort rules",
        "snort.lua": "Snort configuration",
        "install_snort.sh": "Snort installation script",
    }
    
    missing = []
    for path, desc in files.items():
        if Path(path).exists():
            print(f"  ✓ {path:30} - {desc}")
        else:
            print(f"  ✗ {path:30} - {desc} (MISSING)")
            missing.append(path)
    
    if missing:
        print(f"\n❌ Missing files: {len(missing)}")
        return False
    else:
        print("\n✓ All project files present!\n")
        return True


def show_demo_mode():
    """Show demo mode instructions."""
    print_section("DEMO MODE (Recommended for Windows)")
    
    print("The simplest way to get started is with demo mode, which:")
    print("  • Generates realistic sample network traffic data")
    print("  • Trains an ML anomaly detection model")
    print("  • Detects anomalies in the sample data")
    print("  • Generates candidate Snort rules from anomalies")
    print("\nNo Snort installation required!\n")
    
    print("To run the demo:")
    if sys.platform == "win32":
        print("\n  PowerShell:")
        print("    .\\run_demo.ps1\n")
        print("  Or Command Prompt:")
        print("    run_demo.bat\n")
    else:
        print("\n  $ python src/demo.py\n")
    
    print("Expected output:")
    print("  • demo_data/alerts.json               - Sample alerts")
    print("  • demo_output/processed.csv           - Engineered features")
    print("  • demo_output/model.joblib            - Trained model")
    print("  • demo_output/scaler.joblib           - Normalization scaler")
    print("  • demo_output/results.json            - Detection results")
    print("  • demo_output/generated_rules.rules   - Generated Snort rules")
    print("  • demo_output/generated_rules_metadata.json - Rule metadata\n")


def show_production_mode():
    """Show production mode instructions."""
    print_section("PRODUCTION MODE (Linux/WSL + Real Snort)")
    
    print("For real network monitoring with Snort IDS:\n")
    
    print("Step 1: Install Snort 3")
    print("  $ sudo bash install_snort.sh\n")
    
    print("Step 2: Run Snort to generate real alerts")
    print("  $ snort -c snort.lua -i <interface> -A json\n")
    
    print("Step 3: Train model on baseline/normal traffic")
    print("  $ python src/train.py\n")
    
    print("Step 4: Run real-time anomaly detection")
    print("  $ python src/detect.py\n")
    
    print("Step 5: Start real-time monitor (optional)")
    print("  $ python src/monitor.py\n")
    
    print("This generates:")
    print("  • Anomaly detection results from real Snort alerts")
    print("  • Candidate Snort rules from detected anomalies")
    print("  • Real-time monitoring of new alerts\n")


def show_modules():
    """Show information about each module."""
    print_section("Core Modules")
    
    modules = {
        "data_loader.py": [
            "Loads and parses Snort JSON alert files",
            "Extracts network features (src_ip, dst_ip, ports, protocol, etc.)",
            "Handles missing/malformed data gracefully",
            "Converts raw alerts to structured dataframes"
        ],
        "feature_engineering.py": [
            "Converts raw alerts to time-windowed features",
            "Computes: request rates, unique ports, packet sizes, entropy",
            "Normalizes features using StandardScaler",
            "Produces ML-ready dataset for training"
        ],
        "model.py": [
            "Isolation Forest anomaly detection model",
            "Trains on baseline/normal traffic",
            "Scores new data and produces anomaly labels",
            "Saves/loads models using joblib"
        ],
        "rule_generator.py": [
            "Analyzes detected anomalies",
            "Generates candidate Snort rules from patterns",
            "Pattern detection: port scans, DoS, C2, exfiltration",
            "Feedback loop: anomalies → security rules"
        ],
        "demo.py": [
            "Standalone demonstration (no Snort required)",
            "Generates synthetic network traffic",
            "Runs complete pipeline: data → features → model → detection",
            "Perfect for testing on Windows"
        ],
        "train.py": [
            "Trains ML model on baseline alerts",
            "Saves model and scaler for inference",
            "Processes features with selected window size",
            "Produces normalized feature dataset"
        ],
        "detect.py": [
            "Loads trained model and scaler",
            "Runs anomaly detection on new/test data",
            "Generates detection results and anomaly lists",
            "Creates candidate Snort rules from anomalies"
        ],
        "monitor.py": [
            "Real-time incremental monitoring",
            "Watches Snort alert log file for new entries",
            "Processes alerts incrementally (no re-processing)",
            "Detects anomalies as they occur"
        ]
    }
    
    for module, features in modules.items():
        print(f"\n  {module}")
        for feature in features:
            print(f"    • {feature}")


def show_config():
    """Show configuration information."""
    print_section("Configuration (config/config.yaml)")
    
    print("Key settings:\n")
    print("  model:")
    print("    • contamination: 0.05 (expected anomaly rate)")
    print("    • random_state: 42 (reproducibility)\n")
    
    print("  threshold:")
    print("    • anomaly_score: -0.45 (detection threshold)\n")
    
    print("  feature:")
    print("    • window_size: 1min (aggregation window)\n")
    
    print("  paths:")
    print("    • alert_file: Location of Snort JSON alerts")
    print("    • model_path: Where to save trained model")
    print("    • scaler_path: Where to save feature normalization scaler")
    print("    • anomalies_output: Detected anomalies output file\n")


def show_snort_info():
    """Show Snort information."""
    print_section("Snort Configuration")
    
    print("Files:")
    print("  • snort.lua           - Main Snort 3 configuration")
    print("  • local.rules         - Custom detection rules")
    print("  • install_snort.sh    - Installation script for Linux/WSL\n")
    
    print("Key features enabled:")
    print("  • JSON alert output (alert_json)")
    print("  • HTTP inspection and protocol analysis")
    print("  • DNS anomaly detection")
    print("  • Stream reassembly")
    print("  • TCP/UDP/ICMP inspection\n")
    
    print("Custom rules (90+ total):")
    print("  • Port scan detection")
    print("  • HTTP anomalies (SQL injection, XXE, directory traversal)")
    print("  • Traffic threshold and DoS detection")
    print("  • DNS anomalies and C2 beacon patterns")
    print("  • Protocol anomalies (ICMP, fragmentation, etc.)")
    print("  • Data exfiltration patterns")
    print("  • Malware C2 communication detection")
    print("  • Zero-day and exploit detection\n")


def show_workflow():
    """Show the complete workflow."""
    print_section("Complete Workflow")
    
    print("1. DATA INGESTION")
    print("   Raw Snort JSON Alerts")
    print("   ↓\n")
    
    print("2. DATA LOADING & PARSING")
    print("   Load alerts, extract: src/dst IPs, ports, protocol, packet size")
    print("   ↓\n")
    
    print("3. FEATURE ENGINEERING")
    print("   Time-window aggregation")
    print("   Compute: rates, unique ports, packet sizes, entropy")
    print("   Normalize with StandardScaler")
    print("   ↓\n")
    
    print("4. MODEL TRAINING (Baseline)")
    print("   Train Isolation Forest on normal traffic")
    print("   Save model & scaler to disk")
    print("   ↓\n")
    
    print("5. ANOMALY DETECTION")
    print("   Score new data with trained model")
    print("   Label as normal or anomaly")
    print("   Generate anomaly confidence scores")
    print("   ↓\n")
    
    print("6. RULE GENERATION (Feedback Loop)")
    print("   Analyze anomaly patterns")
    print("   Generate candidate Snort rules:")
    print("     - Port scans")
    print("     - DoS/floods")
    print("     - C2 beaconing")
    print("     - Data exfiltration")
    print("   ↓\n")
    
    print("7. VISUALIZATION & OUTPUT")
    print("   results.json         - Detection results")
    print("   anomalies.json       - Flagged anomalies")
    print("   generated_rules.rules - Candidate Snort rules\n")


def show_examples():
    """Show example commands."""
    print_section("Example Commands")
    
    print("Windows (PowerShell):")
    print("  # Run complete demo")
    print("  .\\run_demo.ps1\n")
    
    print("  # Run specific scripts")
    print("  python src\\demo.py")
    print("  python src\\detect.py\n")
    
    print("Linux/WSL:")
    print("  # Install Snort")
    print("  sudo bash install_snort.sh\n")
    
    print("  # Train model")
    print("  python src/train.py\n")
    
    print("  # Run detection")
    print("  python src/detect.py\n")
    
    print("  # Real-time monitoring")
    print("  python src/monitor.py\n")
    
    print("  # Generate rules from anomalies")
    print("  python src/rule_generator.py\n")


def main():
    """Main menu."""
    print_header("CNS - Quick Start Guide")
    
    print("Enhanced Network Security through Custom Snort Rules")
    print("for Zero-Day Attack Detection\n")
    
    # Check system
    if not check_dependencies():
        print("⚠️  Please install dependencies first!")
        sys.exit(1)
    
    if not check_files():
        print("⚠️  Some project files are missing!")
        sys.exit(1)
    
    # Show options
    while True:
        print_header("Main Menu")
        print("\nChoose an option:\n")
        print("  1. Run DEMO MODE (Windows/Linux - No Snort needed)")
        print("  2. Run PRODUCTION MODE (Linux/WSL + Real Snort)")
        print("  3. View module information")
        print("  4. View configuration settings")
        print("  5. View Snort information")
        print("  6. View complete workflow")
        print("  7. View example commands")
        print("  9. Exit\n")
        
        choice = input("Enter your choice (1-9): ").strip()
        
        if choice == "1":
            show_demo_mode()
        elif choice == "2":
            show_production_mode()
        elif choice == "3":
            show_modules()
        elif choice == "4":
            show_config()
        elif choice == "5":
            show_snort_info()
        elif choice == "6":
            show_workflow()
        elif choice == "7":
            show_examples()
        elif choice == "9":
            print("\nGoodbye!\n")
            sys.exit(0)
        else:
            print("\n❌ Invalid choice. Please try again.\n")
            input("Press Enter to continue...")
            os.system('cls' if os.name == 'nt' else 'clear')
            continue


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.\n")
        sys.exit(0)

"""
QUICK START - Run this to test the entire pipeline
"""

if __name__ == '__main__':
    import subprocess
    import sys
    
    print("\n" + "="*60)
    print("CNS: IDS + ML Pipeline - QUICK START")
    print("="*60 + "\n")
    
    # Install dependencies
    print("📦 Installing Python packages...")
    result = subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"])
    if result.returncode != 0:
        print("❌ Failed to install packages")
        sys.exit(1)
    print("✅ Packages installed\n")
    
    # Run demo
    print("🚀 Running ML pipeline demo...")
    result = subprocess.run([sys.executable, "src/demo.py"])
    if result.returncode != 0:
        print("❌ Demo failed")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("✅ PIPELINE COMPLETE")
    print("="*60)
    print("\nOutput files created:")
    print("  📊 demo_data/alerts.json        - 800 sample alerts")
    print("  📈 demo_output/model.joblib     - Trained ML model")
    print("  🔍 demo_output/processed.csv    - Engineered features")
    print("  📋 demo_output/results.json     - Detection results")
    print("\n")
