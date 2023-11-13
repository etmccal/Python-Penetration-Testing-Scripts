import pandas as pd
import re
from openpyxl import Workbook

# Function to load data except CAPEC
def load_data(attack_path, d3fend_path, mappings_path):
    try:
        attack_df = pd.read_excel(attack_path, sheet_name='techniques')
        d3fend_df = pd.read_csv(d3fend_path)
        d3fend_full_mappings_df = pd.read_csv(mappings_path)
    except FileNotFoundError as e:
        raise e

    return attack_df, d3fend_df, d3fend_full_mappings_df

# Function to clean data
def clean_data_for_output(data_value):
    if pd.isnull(data_value):
        return ''
    return re.sub(r'\s+', ' ', str(data_value).replace(':', '').replace('\n', '').replace('\r', '').strip())

# Function to parse CAPEC file and create a mapping
def parse_capec_file(filepath):
    capec_df = pd.read_csv(filepath)

    capec_mapping = {}
    for index, row in capec_df.iterrows():
        attack_ids = re.findall(r'ENTRY ID:(\d+(?:\.\d+)?)', str(row['Related Weaknesses'])) if pd.notnull(row['Related Weaknesses']) else []
        
        # Prepare the CAPEC entry
        capec_entry = {
            'CAPEC ID': str(row.get('ID', index)).strip(),
            'CAPEC Name': str(row["'ID"]).strip(),
            'Likelihood Of Attack': str(row.get('Likelihood Of Attack', '')).strip(),
            'Typical Severity': str(row.get('Related Attack Patterns', '')).strip(),
            'Description': str(row.get('Status', '')).strip(),
            'CWE IDs': str(row.get('Example Instances', '')).strip()
        }
        
        # Create mapping for each ATT&CK ID
        for attack_id in attack_ids:
            # Ensure the 'T' prefix is present
            formatted_attack_id = f"T{attack_id}" if not attack_id.startswith('T') else attack_id
            capec_mapping.setdefault(formatted_attack_id, []).append(capec_entry)

    return capec_mapping

# Function to find related CAPEC entries
def find_related_capec_entries(attack_id, capec_mapping):
    return capec_mapping.get(attack_id, [])

# Function to map artifacts to threats
def map_artifacts_to_threats(artifacts, countermeasures, attack_data, d3fend_mappings, capec_mapping):
    grouped_mappings = {}

    for artifact, countermeasure in zip(artifacts, countermeasures):
        corrected_artifact = artifact.strip().lower()

        # Search for related TTPs in the ATT&CK dataset based on the artifact
        related_ttps = attack_data[attack_data['data sources'].str.contains(r'\b' + re.escape(corrected_artifact) + r'\b', na=False, regex=True, case=False)]

        if related_ttps.empty:
            continue

        # Process each related TTP
        for _, ttp in related_ttps.iterrows():
            attack_id = ttp['ID']
            key = (artifact, attack_id)

            # Initialize the mapping for the key
            if key not in grouped_mappings:
                artifact_relationships = d3fend_mappings[d3fend_mappings['off_tech'].str.contains(r'\b' + re.escape(attack_id) + r'\b', na=False, regex=True)]['off_artifact_rel_label']
                relationship_string = ', '.join(artifact_relationships.unique())  # Convert to string

                grouped_mappings[key] = {
                    'Artifact Name': artifact,
                    'Countermeasures': set(),
                    'Related ATT&CK TTP ID': attack_id,
                    'Related ATT&CK TTP Name': clean_data_for_output(ttp['name']),
                    'Related ATT&CK TTP Description': clean_data_for_output(ttp['description']),
                    'ATT&CK TTP Stages': clean_data_for_output(ttp['tactics']),
                    'ATT&CK TTP Artifact Relationship': relationship_string,
                    'Related D3FEND Technique Relationships': set(),
                    'Related D3FEND Technique Name': set(),
                    'Detection': clean_data_for_output(ttp['detection']),
                    'Platforms': clean_data_for_output(ttp['platforms']),
                    'Permissions Required': clean_data_for_output(ttp['permissions required']),
                    'Effective Permissions': clean_data_for_output(ttp['effective permissions']),
                    'Related CAPEC Entries': []
                }

            # Add countermeasures and related CAPEC entries
            grouped_mappings[key]['Countermeasures'].add(countermeasure)
            related_capec_entries = find_related_capec_entries(attack_id, capec_mapping)
            grouped_mappings[key]['Related CAPEC Entries'].extend(related_capec_entries)

            # Find related D3FEND entries based on ATT&CK ID
            related_d3fend_entries = d3fend_mappings[d3fend_mappings['off_tech'].str.contains(r'\b' + re.escape(attack_id) + r'\b', na=False, regex=True)]
            for _, d3fend_entry in related_d3fend_entries.iterrows():
                d3fend_id = d3fend_entry['def_artifact_rel_label']
                d3fend_name = d3fend_entry['def_tech_label']
                # Concatenate d3fend_id and d3fend_name with a delimiter (e.g., " - ")
                d3fend_combined = f"{d3fend_id} - {d3fend_name}"
                grouped_mappings[key]['Related D3FEND Technique Relationships'].add(d3fend_combined)
                grouped_mappings[key]['Related D3FEND Technique Name'].add(d3fend_name)

    return [data for key, data in grouped_mappings.items()]

# Function to create the threat modeling workbook
def create_threat_modeling_workbook(scenario_name, scenario_objective, scenario_actors, actors_trust, artifact_mappings):
    if not artifact_mappings:
        return None

    wb = Workbook()
    ws = wb.active
    ws.title = "Threat Modeling"

    headers = [
        'Threat Scenario Name', 'Threat Scenario Objective', 'Threat Scenario Actor(s)',
        'Level of Trust', 'Artifact Name', 'Countermeasures',
        'Related ATT&CK TTP ID', 'Related ATT&CK TTP Name', 'Related ATT&CK TTP Description',
        'ATT&CK TTP Stages', 'ATT&CK TTP Artifact Relationship', 'Related D3FEND Technique Name',
        'Related D3FEND Technique Relationships', 'Platforms', 'Permissions Required', 'Effective Permissions',
        'Related CAPEC IDs', 'Related CAPEC Names', 'CAPEC Summaries', 
        'Likelihoods Of Attack', 'Typical Severities','CWE IDs', 'Detection'
    ]
    ws.append(headers)

    for mapping in artifact_mappings:
        capec_ids = '; '.join([entry['CAPEC ID'] for entry in mapping['Related CAPEC Entries']])
        capec_names = '; '.join([entry['CAPEC Name'] for entry in mapping['Related CAPEC Entries']])
        likelihoods_of_attack = '; '.join([entry['Likelihood Of Attack'] for entry in mapping['Related CAPEC Entries']])
        typical_severities = '; '.join([entry['Typical Severity'] for entry in mapping['Related CAPEC Entries']])
        descriptions = '; '.join([entry['Description'] for entry in mapping['Related CAPEC Entries']])
        cwe_ids = '::'.join([entry['CWE IDs'] for entry in mapping['Related CAPEC Entries']])
        d3fend_combined_info = '; '.join(mapping['Related D3FEND Technique Relationships'])

        row = [
            scenario_name, scenario_objective, scenario_actors, actors_trust,
            mapping['Artifact Name'], ', '.join(mapping['Countermeasures']),
            mapping['Related ATT&CK TTP ID'], mapping['Related ATT&CK TTP Name'],
            mapping['Related ATT&CK TTP Description'], mapping['ATT&CK TTP Stages'],
            ', '.join(mapping['ATT&CK TTP Artifact Relationship']) if isinstance(mapping['ATT&CK TTP Artifact Relationship'], list) else str(mapping['ATT&CK TTP Artifact Relationship']),
            ', '.join(mapping['Related D3FEND Technique Name']), d3fend_combined_info,
            mapping['Platforms'], mapping['Permissions Required'],
            mapping['Effective Permissions'], capec_ids, capec_names, 
            descriptions, likelihoods_of_attack, typical_severities, cwe_ids, 
            mapping['Detection']
        ]
        ws.append(row)

    filename = f"threat_modeling_{scenario_name.replace(' ', '_')}.xlsx"
    wb.save(filename)
    return filename

def main():
    scenario_name = input("Enter Threat Scenario Name: ")
    scenario_objective = input("Enter Threat Scenario Objective: ")
    scenario_actors = input("Enter Threat Scenario Actor(s): ")
    actors_trust = input("Trust Level: ")

    attack_path = 'enterprise-attack-v14.0.xlsx'
    d3fend_path = 'd3fend.csv'
    mappings_path = 'd3fend-full-mappings.csv'

    attack_df, d3fend_df, d3fend_full_mappings_df = load_data(attack_path, d3fend_path, mappings_path)
    capec_mapping = parse_capec_file('658 2.csv')

    artifacts = []
    countermeasures = []
    
    while True:
        artifact_name = input("Enter Digital Artifact Name (or type 'done' to finish): ")
        if artifact_name.lower() == 'done':
            break
        countermeasures_input = input(f"Enter Countermeasures for {artifact_name}, separated by commas if multiple: ")
        countermeasure_list = [cm.strip() for cm in countermeasures_input.split(',')]
        artifacts.extend([artifact_name] * len(countermeasure_list))
        countermeasures.extend(countermeasure_list)

    artifact_mappings = map_artifacts_to_threats(artifacts, countermeasures, attack_df, d3fend_full_mappings_df, capec_mapping)
    
    if not artifact_mappings:
        print("No artifact mappings found. Exiting without creating a workbook.")
        return

    output_filename = create_threat_modeling_workbook(scenario_name, scenario_objective, scenario_actors, actors_trust, artifact_mappings)
    if output_filename:
        print(f"Threat Modeling Workbook created: {output_filename}")
    else:
        print("No workbook created as no mappings were found.")

if __name__ == "__main__":
    main()
