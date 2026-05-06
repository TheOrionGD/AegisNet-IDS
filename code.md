# Key Code Snippets for CNS SIEM Project Report (Total: 278 lines)

1. run_system.py 

**Core Boot Sequence - Port Management + Service Startup:**
```python
def boot(self):
    print("\n" + "=" * 60)
    print("  AEGISNET SIEM: UNIFIED SYSTEM BOOT")
    print("=" * 60 + "\n")

    # Port lock for API
    if self.is_port_in_use(self.api_port):
        logger.warning(f"Port {self.api_port} busy. Waiting...")
        if not self.wait_for_port_free(self.api_port, timeout=10):
            sys.exit(1)

    # 1. FastAPI + Health Check
    self.start_process("SIEM API", [
        self.python_exe, "-m", "uvicorn", "api.main:app",
        "--host", "0.0.0.0", "--port", str(self.api_port)
    ], cwd=self.root_dir / "back-end", log_file="api.log")
    
    if not self.check_api_health(retries=60, delay=3):
        logger.error("API health check failed.")
        sys.exit(1)

    # 2-3. Core Workers
    self.start_process("Analysis Worker", [self.python_exe, "core/analysis_worker.py"],
                      cwd=self.root_dir / "back-end", log_file="analysis_worker.log")
    time.sleep(2)
    self.start_process("SOAR Worker", [self.python_exe, "core/soar_worker.py"],
                      cwd=self.root_dir / "back-end", log_file="soar_worker.log")

    # 4. Snort Bridge
    alert_log = self.root_dir / "alert_json.txt"
    alert_log.touch(exist_ok=True)
    self.start_process("Snort Bridge", [
        self.python_exe, "core/snort_bridge.py",
        f"http://localhost:{self.api_port}", str(alert_log)
    ], cwd=self.root_dir / "back-end", log_file="snort_bridge.log")

    threading.Thread(target=self.monitor_processes, daemon=True).start()
    print(f"READY | API: http://localhost:{self.api_port}")
```


2. api/main.py 

**Startup - Infra + Background Services:**
```python
@app.on_event("startup")
async def startup_event():
    await verify_infrastructure()  # MongoDB + Storage
    
    await bus.initialize()
    bus.subscribe("incident", broadcast_incident)
    background_tasks.add(asyncio.create_task(bus.consume(group="dashboard_group")))

    # Async init: ML Engine + SIEM Pipeline
    async def init_ml():
        get_realtime_engine().load_models()
        logger.info("ML Engine ready")
    
    async def init_pipeline():
        get_siem_pipeline().initialize()
        logger.info("SIEM Pipeline ready")
    
    background_tasks.add(asyncio.create_task(init_ml()))
    background_tasks.add(asyncio.create_task(init_pipeline()))
```


3. detect.py 

**Batch Processing + Rule Gen:**
```python
def main():
    cfg = load_config()
    model = AnomalyModel().load_model(cfg['paths']['model_path'])
    engineer = FeatureEngineer(window_size=cfg['feature']['window_size'])
    engineer.scaler = joblib.load(cfg['paths']['scaler_path'])

    df = DataLoader(cfg['paths']['log_dir'], cfg['paths']['alert_file']).load_logs()
    features = engineer.extract_features(df)
    scores, labels = model.predict(engineer.normalize_features(features)[0])

    results = []
    for idx, (window, score, label) in enumerate(zip(features.index, scores, labels)):
        results.append({
            'window_start': window.isoformat(),
            'score': float(score),
            'label': 'anomaly' if label == -1 else 'normal'
        })

    json.dump({'results': results}, open(cfg['paths']['detection_results_output'], 'w'), indent=2)
    
    anomalies = [r for r in results if r['label'] == 'anomaly']
    json.dump(anomalies, open(cfg['paths']['anomalies_output'], 'w'), indent=2)
    
    if anomalies:
        RuleGenerator('generated_rules.rules').analyze_anomalies(df, anomalies)
```

4. monitor.py 

**Incremental Processing:**
```python
class IncrementalLogHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.offsets = self._load_state()
        self.model = AnomalyModel().load_model(config['paths']['model_path'])
        self.engineer = FeatureEngineer()
        self.engineer.scaler = joblib.load(config['paths']['scaler_path'])

    def process_file(self, path):
        offset = self.offsets.get(str(path), 0)
        entries = []
        with open(path, 'r', errors='ignore') as f:
            f.seek(offset)
            for line in f:
                try:
                    parsed = DataLoader()._extract_fields(json.loads(line.strip()))
                    entries.append(parsed)
                except: continue
            self.offsets[str(path)] = f.tell()
            self._save_state()

        if entries:
            df = pd.DataFrame(entries)
            features = self.engineer.extract_features(df)
            scores, labels = self.model.predict(self.engineer.normalize_features(features)[0])
            
            anomalies = []
            for w, s, l in zip(features.index, scores, labels):
                if l == -1 or s < self.config['threshold']['anomaly_score']:
                    anomalies.append({'window': w.isoformat(), 'score': s, 'file': str(path)})
            
            if anomalies:
                with open(self.anomalies_path, 'a') as f:
                    for a in anomalies: f.write(json.dumps(a) + '\n')
```

5. adaptive_learning.py

**Self-Learning Core:**
```python
class AdaptiveLearningEngine:
    LABELS = {"confirmed_true_positive", "false_positive", "unknown"}
    
    def __init__(self, rolling_window=500, min_retrain=20):
        self._buffer, self._lock = [], threading.Lock()
        self.rolling_window = rolling_window
        self.min_retrain = min_retrain

    def ingest_sample(self, features, label, incident_id=None):
        if label not in self.LABELS:
            raise ValueError("Invalid label")
        entry = {"features": features, "label": label}
        with self._lock:
            self._buffer.append(entry)
            if len(self._buffer) > self.rolling_window:
                self._buffer.pop(0)

    def maybe_retrain(self):
        with self._lock:
            labeled = [s for s in self._buffer if s["label"] != "unknown"]
        if len(labeled) < self.min_retrain:
            return None
        
        # Retrain IsolationForest on labeled data
        X = np.array([s["features"] for s in labeled])
        y = np.array([0 if s["label"] == "confirmed_true_positive" else 1 for s in labeled])
        new_model = IsolationForest(contamination=0.1).fit(X)
        self.save_model(new_model, version=self._version_counter + 1)
        return ModelVersion(...)  # New active model
```

6. index.html
```
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>aegisnet</title>
    </head>
    <body>
        <div id="root"></div>
        <script type="module" src="/src/main.jsx"></script>
    </body>
    </html>
```