import pandas as pd
import os
import glob

FOLDER_PATH = os.path.join(os.path.expanduser('~'), 'graduation_project/data/waap_dataset_2026/')

print(f"Looking for CSV files in: {FOLDER_PATH}")

csv_files = glob.glob(os.path.join(FOLDER_PATH, "*.csv"))

if csv_files:
    target_file = csv_files[0]
    print(f"\n SUCCESS: Found {len(csv_files)} files.")
    print(f"Inspecting File: {os.path.basename(target_file)}")
    print("=" * 60)

    try:
        df = pd.read_csv(target_file, nrows=100000)

        df.columns = df.columns.str.strip()
        
        print("\n --- Dataset Info ---")
        df.info()

        print("\n --- First 5 Rows Sample ---")
        print(df.head())

        missing_values = df.isnull().sum().sum()
        print(f"\n --- Total Missing Values: {missing_values} ---")

        label_col = next((col for col in df.columns if col.lower() == 'label'), None)
        
        print("\n --- Attack Distribution (Labels) ---")
        if label_col:
            print(f"Found Label Column: '{label_col}'")
            print(df[label_col].value_counts())
        else:
            print(" Warning: Could not find a 'label' column!")
            print("Available columns:", df.columns.tolist())
            
    except Exception as e:
        print(f"Error reading the file: {e}")

else:
    print("\nError: No CSV files found!")
    print(f"Please check directory: {FOLDER_PATH}")
