#!/usr/bin/env python3
"""
Real-Time Cyber Security Log Correlation Using Apache Kafka
Exploratory Data Analysis (EDA) on Network Flow Parquet Datasets
"""

import os
import glob
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pyarrow.parquet as pq

# Set style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'Helvetica, Arial, DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cccccc'
plt.rcParams['axes.linewidth'] = 0.8

BASE_DIR = '/Users/yashna/edaspa/EDA'
PLOTS_DIR = os.path.join(BASE_DIR, 'plots')
DATA_DIR = '/Users/yashna/Downloads/archive'

os.makedirs(PLOTS_DIR, exist_ok=True)

# Category mapping from filename
CATEGORY_MAP = {
    'Benign-Monday-no-metadata.parquet': 'Benign',
    'Bruteforce-Tuesday-no-metadata.parquet': 'Brute Force',
    'DoS-Wednesday-no-metadata.parquet': 'DoS',
    'Infiltration-Thursday-no-metadata.parquet': 'Infiltration',
    'WebAttacks-Thursday-no-metadata.parquet': 'Web Attacks',
    'Botnet-Friday-no-metadata.parquet': 'Botnet',
    'DDoS-Friday-no-metadata.parquet': 'DDoS',
    'Portscan-Friday-no-metadata.parquet': 'Port Scan'
}

print("="*60)
print("STEP 1: DATASET INVENTORY")
print("="*60)

file_paths = sorted(glob.glob(os.path.join(DATA_DIR, '*.parquet')))
inventory_records = []

for fpath in file_paths:
    fname = os.path.basename(fpath)
    cat = CATEGORY_MAP.get(fname, 'Unknown')
    meta = pq.read_metadata(fpath)
    schema = pq.read_schema(fpath)
    size_bytes = os.path.getsize(fpath)
    size_mb = size_bytes / (1024 * 1024)
    num_rows = meta.num_rows
    num_cols = meta.num_columns
    
    inventory_records.append({
        'Dataset': fname,
        'Category': cat,
        'Rows': num_rows,
        'Columns': num_cols,
        'File Size (MB)': round(size_mb, 2),
        'File Size (Bytes)': size_bytes
    })
    print(f"File: {fname:42} | Category: {cat:12} | Rows: {num_rows:8,d} | Cols: {num_cols:2d} | Size: {size_mb:6.2f} MB")

inventory_df = pd.DataFrame(inventory_records)
inventory_df.to_csv(os.path.join(BASE_DIR, 'dataset_summary.csv'), index=False)
print("\nDataset Summary saved to dataset_summary.csv")
print(f"Total Rows across 8 files: {inventory_df['Rows'].sum():,d}")
print(f"Total Size across 8 files: {inventory_df['File Size (MB)'].sum():.2f} MB")

print("\n" + "="*60)
print("STEP 2: LOADING AND COMBINING DATASET")
print("="*60)

dfs = []
for fpath in file_paths:
    fname = os.path.basename(fpath)
    cat = CATEGORY_MAP.get(fname, 'Unknown')
    print(f"Loading {fname}...")
    df_temp = pd.read_parquet(fpath)
    # Add derived columns
    df_temp['category'] = cat
    df_temp['traffic_type'] = 'Benign' if cat == 'Benign' else 'Attack'
    dfs.append(df_temp)

combined_df = pd.concat(dfs, ignore_index=True)
print(f"\nCombined Dataset Shape: {combined_df.shape}")
print(f"Total Records: {len(combined_df):,d}")

# Identify feature types
original_features = [c for c in combined_df.columns if c not in ['category', 'traffic_type']]
num_original_features = len(original_features)

numerical_features = combined_df[original_features].select_dtypes(include=[np.number]).columns.tolist()
categorical_features = combined_df[original_features].select_dtypes(include=['object', 'category', 'string']).columns.tolist()
datetime_features = combined_df[original_features].select_dtypes(include=['datetime', 'datetimetz']).columns.tolist()

print(f"Original Features: {num_original_features}")
print(f"Numerical Features ({len(numerical_features)}): {numerical_features[:5]}... and {len(numerical_features)-5} more")
print(f"Categorical Features ({len(categorical_features)}): {categorical_features}")
print(f"Datetime Features ({len(datetime_features)}): {datetime_features}")

print("\n" + "="*60)
print("STEP 3: CLASS / CATEGORY DISTRIBUTION")
print("="*60)

cat_counts = combined_df['category'].value_counts()
cat_pcts = combined_df['category'].value_counts(normalize=True) * 100

cat_dist_df = pd.DataFrame({
    'Category': cat_counts.index,
    'Records': cat_counts.values,
    'Percentage (%)': cat_pcts.values
})
print(cat_dist_df.to_string(index=False))

traffic_counts = combined_df['traffic_type'].value_counts()
traffic_pcts = combined_df['traffic_type'].value_counts(normalize=True) * 100

print("\nTraffic Type Distribution:")
traffic_dist_df = pd.DataFrame({
    'Traffic Type': traffic_counts.index,
    'Records': traffic_counts.values,
    'Percentage (%)': traffic_pcts.values
})
print(traffic_dist_df.to_string(index=False))

# Also check original Label column distribution
print("\nGranular Original 'Label' Column Distribution:")
label_counts = combined_df['Label'].value_counts()
print(label_counts)

# Generate Plots
# 1. Category Distribution Bar Chart
plt.figure(figsize=(10, 6), dpi=300)
palette = sns.color_palette('viridis', len(cat_counts))
bars = plt.bar(cat_counts.index, cat_counts.values, color=palette, edgecolor='black', alpha=0.85)
plt.title('Number of Network Events by Category', fontsize=15, fontweight='bold', pad=15)
plt.xlabel('Category', fontsize=12, fontweight='bold')
plt.ylabel('Number of Events', fontsize=12, fontweight='bold')
plt.xticks(rotation=30, ha='right', fontsize=11)
plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,d}'))

# Add data labels
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2., height + 10000,
             f'{height:,d}\n({(height/len(combined_df)*100):.1f}%)',
             ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.ylim(0, max(cat_counts.values) * 1.15)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'category_distribution.png'), dpi=300)
plt.close()
print("Saved: plots/category_distribution.png")

# 2. Benign vs Attack Traffic Pie Chart
plt.figure(figsize=(8, 7), dpi=300)
colors = ['#2b5c8f', '#d95f02']
explode = (0.05, 0.05)
plt.pie(traffic_counts, labels=traffic_counts.index, autopct='%1.2f%%', startangle=140,
        colors=colors, explode=explode, textprops={'fontsize': 12, 'fontweight': 'bold'},
        wedgeprops={'edgecolor': 'black', 'linewidth': 1.2, 'antialiased': True}, shadow=True)
plt.title('Benign vs Attack Traffic Distribution\n(Total: {:,d} Events)'.format(len(combined_df)), fontsize=14, fontweight='bold', pad=15)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'benign_vs_attack.png'), dpi=300)
plt.close()
print("Saved: plots/benign_vs_attack.png")

# 3. Attack Category Distribution (Excluding Benign)
attack_df = combined_df[combined_df['category'] != 'Benign']
attack_cat_counts = attack_df['category'].value_counts()
plt.figure(figsize=(10, 6), dpi=300)
palette_attack = sns.color_palette('magma', len(attack_cat_counts))
bars_attack = plt.bar(attack_cat_counts.index, attack_cat_counts.values, color=palette_attack, edgecolor='black', alpha=0.85)
plt.title('Attack Category Distribution (Excluding Benign)\n(Total Attacks: {:,d})'.format(len(attack_df)), fontsize=15, fontweight='bold', pad=15)
plt.xlabel('Attack Category', fontsize=12, fontweight='bold')
plt.ylabel('Number of Attack Events', fontsize=12, fontweight='bold')
plt.xticks(rotation=30, ha='right', fontsize=11)
plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,d}'))

for bar in bars_attack:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2., height + 8000,
             f'{height:,d}\n({(height/len(attack_df)*100):.1f}%)',
             ha='center', va='bottom', fontsize=9, fontweight='bold')

plt.ylim(0, max(attack_cat_counts.values) * 1.15)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'attack_distribution.png'), dpi=300)
plt.close()
print("Saved: plots/attack_distribution.png")

print("\n" + "="*60)
print("STEP 4: MISSING VALUES ANALYSIS")
print("="*60)

missing_counts = combined_df.isnull().sum()
missing_pcts = (missing_counts / len(combined_df)) * 100
missing_df = pd.DataFrame({
    'Feature': missing_counts.index,
    'Missing Count': missing_counts.values,
    'Missing Percentage (%)': missing_pcts.values
})
missing_df.to_csv(os.path.join(BASE_DIR, 'missing_values.csv'), index=False)

total_missing = missing_counts.sum()
features_with_missing = missing_df[missing_df['Missing Count'] > 0]

if len(features_with_missing) == 0:
    print("No missing values detected across all features.")
else:
    print(f"Detected missing values in {len(features_with_missing)} features:")
    print(features_with_missing.to_string(index=False))
    
    # Generate missing values plot if any
    plt.figure(figsize=(10, 5), dpi=300)
    plt.barh(features_with_missing['Feature'], features_with_missing['Missing Count'], color='#e74c3c')
    plt.title('Missing Value Count by Feature', fontsize=14, fontweight='bold')
    plt.xlabel('Missing Count', fontsize=12)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'missing_values.png'), dpi=300)
    plt.close()
    print("Saved: plots/missing_values.png")

print("\n" + "="*60)
print("STEP 5: DUPLICATE ANALYSIS")
print("="*60)

# Duplicate analysis on original features
duplicate_count = combined_df.duplicated(subset=original_features).sum()
duplicate_pct = (duplicate_count / len(combined_df)) * 100
print(f"Total duplicate rows (across original features): {duplicate_count:,d}")
print(f"Duplicate percentage: {duplicate_pct:.2f}%")
print("Note: Duplicate flows are preserved per requirement; in network security logs, recurring heartbeat flows, identical port scans, and SYN floods naturally produce duplicate 5-tuple/flow metric records.")

print("\n" + "="*60)
print("STEP 6: DATA TYPE ANALYSIS")
print("="*60)

dtype_records = []
for col in combined_df.columns:
    dtype_records.append({
        'Feature': col,
        'Data Type': str(combined_df[col].dtype),
        'Unique Values': combined_df[col].nunique(),
        'Missing Values': int(combined_df[col].isnull().sum())
    })
dtype_df = pd.DataFrame(dtype_records)
print(dtype_df.head(20).to_string(index=False))
print(f"... (total {len(dtype_df)} features)")

print(f"\nSummary of Feature Types:")
print(f"- Numerical features: {len(numerical_features)}")
print(f"- Categorical features: {len(categorical_features) + 2} (including derived 'category' and 'traffic_type')")
print(f"- Datetime features: {len(datetime_features)}")

print("\n" + "="*60)
print("STEP 7: DESCRIPTIVE STATISTICS")
print("="*60)

# Compute descriptive statistics on numerical columns
desc_stats = combined_df[numerical_features].describe(percentiles=[0.25, 0.5, 0.75]).T
desc_stats = desc_stats[['count', 'mean', 'std', 'min', '25%', '50%', '75%', 'max']]
desc_stats.rename(columns={'50%': 'median'}, inplace=True)
desc_stats.to_csv(os.path.join(BASE_DIR, 'descriptive_statistics.csv'))
print("Descriptive statistics calculated for all numerical features and saved to descriptive_statistics.csv")
print("\nSample Descriptive Statistics:")
print(desc_stats.head(10).round(2).to_string())

print("\n" + "="*60)
print("STEP 8: IMPORTANT NETWORK FLOW FEATURES & DISTRIBUTIONS")
print("="*60)

# Select 8 highly meaningful network features present in dataset
key_features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packets Length Total',
    'Bwd Packets Length Total',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Packet Length Mean',
    'Init Fwd Win Bytes'
]

# Verify all key features exist
key_features = [f for f in key_features if f in combined_df.columns]
print(f"Selected Key Network Features ({len(key_features)}): {key_features}")

# Visualizing Distributions (Log-scaled / Histograms for skewed network data)
fig, axes = plt.subplots(4, 2, figsize=(16, 18), dpi=300)
axes = axes.flatten()

for i, feat in enumerate(key_features[:8]):
    ax = axes[i]
    # Sample 100,000 for responsive and clean KDE/hist plotting
    sample_data = combined_df[feat].dropna().sample(min(100000, len(combined_df)), random_state=42)
    # Log1p transformation for visualization of heavy-tailed network metrics
    pos_data = sample_data[sample_data >= 0]
    log_data = np.log1p(pos_data)
    
    sns.histplot(log_data, kde=True, ax=ax, color='#1f77b4', bins=40, edgecolor='black', alpha=0.6)
    ax.set_title(f'Distribution of {feat} (Log1p Scale)', fontsize=12, fontweight='bold')
    ax.set_xlabel(f'log1p({feat})', fontsize=10)
    ax.set_ylabel('Frequency', fontsize=10)

plt.suptitle('Histograms & Density of Key Network Flow Features (Log1p Transformed)', fontsize=16, fontweight='bold', y=0.99)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'numerical_distributions.png'), dpi=300)
plt.close()
print("Saved: plots/numerical_distributions.png")

# Boxplots by Traffic Type for Key Features
fig, axes = plt.subplots(4, 2, figsize=(16, 18), dpi=300)
axes = axes.flatten()

sample_df = combined_df.sample(min(100000, len(combined_df)), random_state=42)

for i, feat in enumerate(key_features[:8]):
    ax = axes[i]
    sample_feat = sample_df[['traffic_type', feat]].dropna()
    sample_feat['log_val'] = np.log1p(sample_feat[feat].clip(lower=0))
    sns.boxplot(x='traffic_type', y='log_val', data=sample_feat, ax=ax, palette=['#2b5c8f', '#d95f02'], hue='traffic_type', legend=False)
    ax.set_title(f'{feat} by Traffic Type (Log1p Scale)', fontsize=12, fontweight='bold')
    ax.set_xlabel('Traffic Type', fontsize=10, fontweight='bold')
    ax.set_ylabel(f'log1p({feat})', fontsize=10)

plt.suptitle('Comparison of Key Network Flow Metrics: Benign vs Attack (Log1p Scale)', fontsize=16, fontweight='bold', y=0.99)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'feature_boxplots.png'), dpi=300)
plt.close()
print("Saved: plots/feature_boxplots.png")

print("\n" + "="*60)
print("STEP 9: CORRELATION ANALYSIS")
print("="*60)

# Full numerical correlation matrix
print("Computing full Pearson correlation matrix...")
corr_matrix = combined_df[numerical_features].corr(method='pearson')
corr_matrix.to_csv(os.path.join(BASE_DIR, 'correlation_matrix.csv'))
print("Full correlation matrix saved to correlation_matrix.csv")

# Identify top correlated feature pairs (excluding self-correlation and duplicates)
corr_pairs = []
for i in range(len(numerical_features)):
    for j in range(i + 1, len(numerical_features)):
        f1 = numerical_features[i]
        f2 = numerical_features[j]
        val = corr_matrix.loc[f1, f2]
        if not np.isnan(val):
            corr_pairs.append((f1, f2, val, abs(val)))

corr_pairs.sort(key=lambda x: x[3], reverse=True)
top_corr_df = pd.DataFrame(corr_pairs[:15], columns=['Feature 1', 'Feature 2', 'Pearson Correlation', 'Abs Correlation'])
print("\nTop 15 Strongly Correlated Feature Pairs:")
print(top_corr_df[['Feature 1', 'Feature 2', 'Pearson Correlation']].round(4).to_string(index=False))

# Sub-matrix of key representative features for clean visualization heatmap
heatmap_features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packets Length Total',
    'Bwd Packets Length Total',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Flow IAT Mean',
    'Flow IAT Max',
    'Packet Length Mean',
    'Packet Length Std',
    'Init Fwd Win Bytes',
    'Init Bwd Win Bytes',
    'Active Mean',
    'Idle Mean'
]
heatmap_features = [f for f in heatmap_features if f in numerical_features]
sub_corr = combined_df[heatmap_features].corr()

plt.figure(figsize=(14, 11), dpi=300)
mask = np.triu(np.ones_like(sub_corr, dtype=bool))
sns.heatmap(sub_corr, mask=mask, annot=True, fmt='.2f', cmap='coolwarm', vmin=-1, vmax=1,
            square=True, linewidths=0.5, cbar_kws={'shrink': 0.8, 'label': 'Pearson Correlation Coefficient'})
plt.title('Pearson Correlation Heatmap of Key Network Security Flow Features', fontsize=15, fontweight='bold', pad=15)
plt.xticks(rotation=45, ha='right', fontsize=10)
plt.yticks(rotation=0, fontsize=10)
plt.tight_layout()
plt.savefig(os.path.join(PLOTS_DIR, 'correlation_heatmap.png'), dpi=300)
plt.close()
print("Saved: plots/correlation_heatmap.png")

print("\n" + "="*60)
print("STEP 10: TEMPORAL ANALYSIS")
print("="*60)

time_cols = [c for c in combined_df.columns if any(kw in c.lower() for kw in ['time', 'date', 'timestamp'])]
print(f"Timestamp/Date search in columns: {time_cols}")
if len(datetime_features) > 0 or any('timestamp' in c.lower() for c in combined_df.columns):
    print(f"Temporal column identified: {time_cols}")
else:
    print("Finding: No usable temporal column was identified in the provided dataset.")
    print("Explanation: The files are preprocessed 'no-metadata' Parquet files where raw packet timestamps and IP metadata were removed, leaving statistical flow metrics (Flow Duration, IAT, Idle/Active times).")

print("\n" + "="*60)
print("STEP 11: SOURCE / DESTINATION & PROTOCOL ANALYSIS")
print("="*60)

ip_cols = [c for c in combined_df.columns if any(kw in c.lower() for kw in ['ip', 'source ip', 'src_ip', 'dst_ip'])]
port_cols = [c for c in combined_df.columns if any(kw in c.lower() for kw in ['port', 'src_port', 'dst_port'])]
proto_cols = [c for c in combined_df.columns if 'protocol' in c.lower()]

print(f"IP columns found: {ip_cols}")
print(f"Port columns found: {port_cols}")
print(f"Protocol columns found: {proto_cols}")

if 'Protocol' in combined_df.columns:
    proto_counts = combined_df['Protocol'].value_counts()
    proto_map = {6: 'TCP (6)', 17: 'UDP (17)', 0: 'HOPOPT/ICMP (0)'}
    proto_labels = [proto_map.get(p, f'Protocol {p}') for p in proto_counts.index]
    
    proto_df = pd.DataFrame({
        'Protocol Code': proto_counts.index,
        'Protocol Name': proto_labels,
        'Event Count': proto_counts.values,
        'Percentage (%)': (proto_counts.values / len(combined_df)) * 100
    })
    print("\nProtocol Distribution:")
    print(proto_df.to_string(index=False))
    
    # Protocol distribution chart
    plt.figure(figsize=(9, 5), dpi=300)
    bars_proto = plt.bar(proto_labels, proto_counts.values, color=['#2b5c8f', '#e74c3c', '#27ae60'][:len(proto_labels)], edgecolor='black')
    plt.title('Network Protocol Distribution', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Transport Protocol', fontsize=12, fontweight='bold')
    plt.ylabel('Number of Events', fontsize=12, fontweight='bold')
    plt.gca().yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,d}'))
    for bar in bars_proto:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 15000,
                 f'{height:,d}\n({height/len(combined_df)*100:.1f}%)',
                 ha='center', va='bottom', fontsize=9, fontweight='bold')
    plt.ylim(0, max(proto_counts.values)*1.15)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'protocol_distribution.png'), dpi=300)
    plt.close()
    print("Saved: plots/protocol_distribution.png")

    # Protocol by Category breakdown
    proto_cat = pd.crosstab(combined_df['category'], combined_df['Protocol'], normalize='index') * 100
    proto_cat.rename(columns=proto_map, inplace=True)
    print("\nProtocol Breakdown by Attack Category (%):")
    print(proto_cat.round(2).to_string())

    plt.figure(figsize=(11, 6), dpi=300)
    proto_cat.plot(kind='bar', stacked=True, figsize=(11, 6), colormap='tab10', edgecolor='black', alpha=0.85)
    plt.title('Protocol Share (%) Across Traffic Categories', fontsize=14, fontweight='bold')
    plt.xlabel('Category', fontsize=12, fontweight='bold')
    plt.ylabel('Percentage (%)', fontsize=12, fontweight='bold')
    plt.xticks(rotation=30, ha='right', fontsize=10)
    plt.legend(title='Protocol', bbox_to_anchor=(1.02, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'protocol_by_category.png'), dpi=300)
    plt.close()
    print("Saved: plots/protocol_by_category.png")

print("\n" + "="*60)
print("EDA COMPUTATION COMPLETE")
print("="*60)
