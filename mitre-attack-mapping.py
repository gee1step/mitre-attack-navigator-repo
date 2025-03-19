import pandas as pd
import json
import re

# Define the base structure of the JSON
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

# Helper to assign colors and other properties to techniques
def generate_technique_entry(tactic, technique, subtechnique=None):
    return {
        "techniqueID": technique,
        "tactic": tactic,
        "color": "#fca2a2",  # You can adjust this based on tactic or other logic
        "comment": "",
        "enabled": True,
        "metadata": [],
        "links": [],
        "showSubtechniques": bool(subtechnique),
    }

# Function to convert tactic name to the correct format
def format_tactic_name(tactic_name):
    # Convert camelCase to hyphenated lowercase
    # Example: "DefenseEvasion" -> "defense-evasion"
    tactic_name = re.sub('([a-z])([A-Z])', r'\1-\2', tactic_name).lower()
    return tactic_name.strip()

# Function to read Excel file and process it into the JSON format
def process_excel_to_json(excel_file_path):
    # Use pandas to read the Excel file
    df = pd.read_excel(excel_file_path, engine='openpyxl')

    # Debugging: Print the first few rows to check if the data is loaded properly
    print(f"Excel Data Preview: {df.head()}")

    # Process each row in the DataFrame
    for _, row in df.iterrows():
        # Skip rows with 'Disabled' status
        if str(row['status']).strip().lower() == 'disabled':
            continue

        # Ensure the correct columns exist
        if 'tactics' not in row or 'techniques' not in row:
            print("Missing expected columns in the row. Check Excel format.")
            continue

        # Clean tactic list (in case of multiple tactics)
        tactics = str(row['tactics']).strip("[]").replace('"', '').split(',')
        techniques = str(row['techniques']).strip("[]").replace('"', '').split(',')

        for tactic in tactics:
            formatted_tactic = format_tactic_name(tactic.strip())  # Convert tactic to the correct format
            for technique in techniques:
                technique_entry = generate_technique_entry(formatted_tactic, technique.strip())
                json_output['techniques'].append(technique_entry)

# Request the Excel file name from the user
excel_file_path = input("Please enter the Excel file name or path: ")

# Process the Excel file and generate the JSON output
try:
    process_excel_to_json(excel_file_path)
    
    # Output the resulting JSON (you can write it to a file if needed)
    json_string = json.dumps(json_output, indent=4)

    # Print the JSON to the console
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
