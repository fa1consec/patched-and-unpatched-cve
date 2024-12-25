import nvdlib, json
import datetime

def fetch_cves(year):
    start_date = f'{year}-01-01 00:00'
    end_date = f'{year}-01-5 23:59'
    return nvdlib.searchCVE(pubStartDate=start_date, pubEndDate=end_date)

def categorize_cves(cve_data):
    patched_cves = []
    vulnerable_cves = []

    for cve in cve_data:
        description = cve.descriptions[0].value.lower() if cve.descriptions else ""
        
        # Check for keywords indicating a patch or fix
        if 'patch' in description or 'fix' in description:
            patched_cves.append((cve.id, description))
        else:
            vulnerable_cves.append((cve.id, description))
    
    return patched_cves, vulnerable_cves

def save_to_json(cve_list, filename):
    
    with open(filename, "w") as json_file:
        json.dump(cve_list, json_file, indent=4)

    print(f"Data saved to {filename} successfully.")

def main():
    year = 2020
    cve_data = fetch_cves(year)
    
    patched_cves, vulnerable_cves = categorize_cves(cve_data)

 # Save results to JSON file
    save_to_json(patched_cves, f"patched_cves_{year}.json")
    save_to_json(vulnerable_cves, f"vulnerable_cves_{year}.json")

if __name__ == "__main__":
    main()