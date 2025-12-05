import requests

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
BASE_URL = "https://www.virustotal.com/api/v3/files/"

def check_hash_reputation(file_hash):
    headers = {"x-apikey": API_KEY}
    response = requests.get(BASE_URL + file_hash, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"Hash: {file_hash}")
        print(f"Malicious: {stats['malicious']}")
        print(f"Suspicious: {stats['suspicious']}")
    else:
        print("Error querying VirusTotal")

if __name__ == "__main__":
    sample_hash = "44d88612fea8a8f36de82e1278abb02f" # EICAR
    check_hash_reputation(sample_hash)
