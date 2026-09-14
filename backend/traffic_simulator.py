import time
import requests
import random

API_URL = "http://localhost:8000/api/anomaly/detect"

def run_simulation():
    print("==================================================")
    print(" NetShield.AI - Live Traffic & Threat Simulator")
    print("==================================================")
    print(f"Targeting API: {API_URL}")
    print("Simulating real-time network traffic ingestion...")
    print("Press Ctrl+C to stop.\n")
    
    datasets = ["cicids2017", "unsw_nb15"]
    while True:
        try:
            dataset = random.choice(datasets)
            payload = {
                "dataset": dataset,
                "sample_size": random.randint(10, 50)
            }
            res = requests.post(API_URL, json=payload)
            if res.status_code == 200:
                data = res.json()
                if data['new_alerts_created'] > 0:
                    print(f"[!] [{dataset.upper()}] Analyzed: {data['total_analyzed']:<3} | Anomalies: {data['anomalies_detected']:<2} | Alerts Created: {data['new_alerts_created']}")
                else:
                    print(f"[*] [{dataset.upper()}] Analyzed: {data['total_analyzed']:<3} | Normal Traffic Flow")
            else:
                print(f"[ERROR] API returned {res.status_code}: {res.text}")
        except requests.exceptions.ConnectionError:
            print("[WARNING] Backend not reachable. Is FastAPI running on port 8000?")
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            
        time.sleep(random.randint(5, 12))

if __name__ == "__main__":
    run_simulation()
