#!/usr/bin/env python3
"""
Utility script to convert all 8 cybersecurity network-flow Parquet files to CSV.
"""

import os
import glob
import time
import pandas as pd

SOURCE_DIR = '/Users/yashna/Downloads/archive'
TARGET_DIR = '/Users/yashna/edaspa/csv'

os.makedirs(TARGET_DIR, exist_ok=True)

parquet_files = sorted(glob.glob(os.path.join(SOURCE_DIR, '*.parquet')))
print(f"Found {len(parquet_files)} Parquet files to convert in {SOURCE_DIR}\n")

total_start = time.time()

for idx, fpath in enumerate(parquet_files, 1):
    fname = os.path.basename(fpath)
    csv_fname = fname.replace('.parquet', '.csv')
    csv_fpath = os.path.join(TARGET_DIR, csv_fname)
    
    start_time = time.time()
    print(f"[{idx}/{len(parquet_files)}] Converting {fname} -> {csv_fname} ...")
    
    df = pd.read_parquet(fpath)
    df.to_csv(csv_fpath, index=False)
    
    elapsed = time.time() - start_time
    size_mb = os.path.getsize(csv_fpath) / (1024 * 1024)
    print(f"    ✓ Done ({len(df):,d} rows, {len(df.columns)} cols, {size_mb:.2f} MB) in {elapsed:.2f}s")

total_elapsed = time.time() - total_start
total_csv_size = sum(os.path.getsize(os.path.join(TARGET_DIR, f)) for f in os.listdir(TARGET_DIR) if f.endswith('.csv')) / (1024 * 1024)

print("\n" + "="*60)
print(f"All {len(parquet_files)} files successfully converted to CSV in {TARGET_DIR}/")
print(f"Total CSV Size on Disk: {total_csv_size:.2f} MB (~{total_csv_size/1024:.2f} GB)")
print(f"Total Conversion Time: {total_elapsed:.2f} seconds")
print("="*60)
