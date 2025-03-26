import pandas as pd
import json
import re
import requests
from collections import Counter

#define the base structure of the JSON
json_output = {
    "name": "layer",
    "versions": {
        "attack": "16",
        "navigator": "5.1.0",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "filters": {
        "platforms": [
            "Windows", "Linux", "macOS", "Network", "PRE", "Containers", "IaaS", "SaaS", "Office Suite", "Identity Provider"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "aggregateFunction": "average",
        "showID": False,
        "showName": True,
        "showAggregateScores": False,
        "countUnscored": False,
        "expandedSubtechniques": "annotated"
    },
    "hideDisabled": False,
    "techniques": [],
    "gradient": {
        "colors": ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False
}

#helper function to fetch MITRE technique-to-tactic mappings
def fetch_mitre_mappings():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        attack_data = response.json()
        
        technique_tactic_mapping = {}
        
        for obj in attack_data["objects"]:
            if obj.get("type") == "attack-pattern":  # Attack patterns are techniques
                technique_id = next((ext["external_id"] for ext in obj.get("external_references", []) if ext["source_name"] == "mitre-attack"), None)
                tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase["kill_chain_name"] == "mitre-attack"]
                
                if technique_id:
                    technique_tactic_mapping[technique_id] = tactics

        # Debug: Check T1218 mapping
        if "T1218" in technique_tactic_mapping:
            print(f"DEBUG: T1218 mapped to tactics -> {technique_tactic_mapping['T1218']}")
        else:
            print("WARNING: T1218 not found in MITRE data.")

        return technique_tactic_mapping
    except Exception as e:
        print(f"Error fetching MITRE ATT&CK data: {e}")
        return {}

# Fetch the latest MITRE mappings
mitre_mappings = fetch_mitre_mappings()

# Helper function to assign colors based on count
def get_color_for_count(count):
    if count > 10:
        return "#5056b5"
    elif 4 <= count <= 10:
        return "#617fe6"
    else:
        return "#e4ecff"

# Helper function to create technique entries
def generate_technique_entry(tactic, technique, count=0):
    color = get_color_for_count(count)
    return {
        "techniqueID": technique,
        "tactic": tactic,
        "color": color,
        "comment": "",
        "enabled": True,
        "metadata": [],
        "links": [],
        "showSubtechniques": False,
    }

# Function to read Excel file and process it into the JSON format
def process_excel_to_json(excel_file_path):
    df = pd.read_excel(excel_file_path, engine='openpyxl')

    print(f"Excel Data Preview: {df.head()}")  # Debugging step

    technique_count = Counter()

    # Check if 'status' column exists
    if 'status' in df.columns:
        print("Processing rows based on 'status' column...")
        for _, row in df.iterrows():
            if str(row['status']).strip().lower() == 'disabled':
                continue  # Skip disabled techniques
            process_row(row, technique_count)
    else:
        print("No 'status' column found, processing all rows...")
        for _, row in df.iterrows():
            process_row(row, technique_count)

    # Create technique entries while ensuring multiple tactics are assigned properly
    for technique, count in technique_count.items():
        tactics = mitre_mappings.get(technique, [])

        if not tactics:
            print(f"WARNING: No tactic found for {technique}, check MITRE data.")

        for tactic in tactics:
            technique_entry = generate_technique_entry(tactic, technique, count)
            json_output['techniques'].append(technique_entry)

# Function to process each row
def process_row(row, technique_count):
    if 'techniques' not in row:
        print("Missing 'techniques' column. Check Excel format.")
        return

    techniques = str(row['techniques']).strip("[]").replace('"', '').split(',')

    for technique in techniques:
        technique = technique.strip()
        if technique:
            technique_count[technique] += 1  # Count occurrences

# Request the Excel file name from the user
excel_file_path = input("Please enter the Excel file name or path: ")

try:
    process_excel_to_json(excel_file_path)

    # Output the resulting JSON
    json_string = json.dumps(json_output, indent=4)
    print(json_string)

    # Optionally save to a file
    output_file_name = input("Please enter the output JSON file name (e.g., output.json): ")
    with open(output_file_name, 'w', encoding='utf-8') as jsonfile:
        jsonfile.write(json_string)

    print(f"Output saved to {output_file_name}")

except FileNotFoundError:
    print(f"The file {excel_file_path} was not found. Please check the file path and try again.")
except Exception as e:
    print(f"An error occurred: {e}")
