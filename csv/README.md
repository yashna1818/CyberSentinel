# Datasets Directory

The raw CSV flow captures from the **CIC-IDS2017 Dataset** belong in this directory:
- `Benign-Monday-no-metadata.csv`
- `Botnet-Friday-no-metadata.csv`
- `Bruteforce-Tuesday-no-metadata.csv`
- `DDoS-Friday-no-metadata.csv`
- `DoS-Wednesday-no-metadata.csv`
- `Infiltration-Thursday-no-metadata.csv`
- `Portscan-Friday-no-metadata.csv`
- `WebAttacks-Thursday-no-metadata.csv`

> **Note:** Raw CSV files are excluded from version control via `.gitignore` because individual files exceed GitHub's 100 MB file size limit (total dataset is ~740 MB). You can generate or place them here by downloading the official CIC-IDS2017 dataset or converting the parquet files using `convert_parquet_to_csv.py`.
