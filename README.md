# Domain Analysis Tools

A comprehensive suite of Python scripts for analyzing domain registration patterns and checking domain status through WHOIS queries. These tools are designed for cybersecurity researchers, domain analysts, and anyone interested in understanding domain registration trends.

## 🔧 Scripts Overview

### 1. `find_patterns.py` - Domain Pattern & Topic Analysis

Analyzes domain names to identify patterns, classify domains by topic, and generate visualizations of registration trends.

**Key Features:**
- **Topic Classification**: Automatically categorizes domains into:
  - `english`: Domains with primarily English words
  - `mixed-english`: Domains with some English content
  - `non-english`: Domains with non-English content
  - `high-entropy`: Domains with random-like strings (potential DGA domains)
  - `non-english-words`: Domains with non-English character sets
- **Pattern Detection**: Finds common substrings and patterns within domain groups
- **Time Series Analysis**: Creates interactive monthly registration charts
- **Word Cloud Generation**: Visualizes most common terms in domain names
- **Entropy Analysis**: Detects algorithmically generated domains using entropy calculations

### 2. `check_domains.py` - WHOIS Domain Checker

Performs bulk WHOIS queries to check domain registration status, creation dates, and other metadata.

**Key Features:**
- **Load-Balanced WHOIS Queries**: Distributes queries across multiple WHOIS servers
- **Configurable Server Pool**: Supports custom WHOIS server configurations via JSON
- **Comprehensive Status Detection**: Identifies various domain states:
  - Active, NXDOMAIN, Expired, Suspended, In Redemption Period, etc.
- **Data Persistence**: Saves results to CSV and pickle formats
- **Interactive Visualizations**: Generates fullscreen charts showing registration trends
- **Resume Capability**: Can restore and continue from previous runs
- **Multi-threaded Processing**: Concurrent WHOIS queries for faster analysis

## 📋 Requirements

```bash
pip install pandas numpy plotly nltk wordcloud tldextract python-whois argparse
```

**NLTK Data**: The scripts will automatically download required NLTK corpora on first run.

## 🚀 Usage

### Pattern Analysis (`find_patterns.py`)

```bash
# Basic pattern analysis
python find_patterns.py -i domains.csv -o analysis_results.txt

# Filter by date range
python find_patterns.py -i domains.csv -o results.txt -f 2020-01-01 -t 2023-12-31

# Include monthly trend plot
python find_patterns.py -i domains.csv -o results.txt -p

# Filter by domain status
python find_patterns.py -i domains.csv -o results.txt -s active
```

**Arguments:**
- `-i, --input`: Input CSV file containing domain data
- `-o, --output`: Output text file for analysis results
- `-f, --from`: Start date filter (YYYY-MM-DD)
- `-t, --to`: End date filter (YYYY-MM-DD)  
- `-s, --status`: Filter by domain status
- `-p, --plot`: Generate monthly registration plot

### Domain Checking (`check_domains.py`)

```bash
# Check domains from a text file
python check_domains.py -i domain_list.txt -o output_folder

# Use custom worker count and limit
python check_domains.py -i domains.txt -o results -w 10 -l 500

# Force recheck existing domains
python check_domains.py -i domains.txt -o results -f

# Restore from previous run
python check_domains.py -r data_frame.pkl -o results
```

**Arguments:**
- `-i, --input`: Input file with domain list (one per line)
- `-o, --output`: Output folder for results
- `-w, --workers`: Number of concurrent threads (default: 5)
- `-l, --limit`: Maximum domains to process
- `-f, --force`: Force recheck existing domains
- `-r, --restore`: Restore from saved DataFrame

## 📊 Output Files

### Pattern Analysis Outputs
- **`analysis_results.txt`**: Detailed topic breakdown and identified patterns
- **`wordcloud.png`**: Visual representation of common domain terms
- **`domains_per_month.html`**: Interactive time series chart

### Domain Checking Outputs
- **`domains.csv`**: Complete domain information including WHOIS data
- **`data_frame.pkl`**: Serialized DataFrame for quick restoration
- **`domain_registrations_chart.html`**: Fullscreen interactive registration timeline

## 🔍 CSV Format Requirements

### For Pattern Analysis
Expected CSV columns (flexible naming):
- Domain name column (containing 'domain' in header)
- Creation date column (containing 'created' in header)
- Status column (containing 'status' in header, optional)

### Example CSV Structure
```csv
Domain,Created,Status
example.com,2020-01-15,active
test.org,2021-03-22,expired
random123.net,2019-11-08,active
```

## 🎯 Use Cases

- **Cybersecurity Research**: Identify suspicious domain patterns and DGA domains
- **Brand Protection**: Monitor domain registrations for brand abuse
- **Market Analysis**: Track domain registration trends over time
- **Academic Research**: Study domain naming patterns and linguistic analysis
- **Threat Intelligence**: Analyze domain infrastructure of threat actors

## ⚙️ Advanced Configuration

### WHOIS Server Configuration
Create a `whois_servers.json` file to customize WHOIS servers:

```json
{
  "com": [
    "whois.verisign-grs.com",
    "whois.internic.net"
  ],
  "org": [
    "whois.pir.org"
  ],
  "default": [
    "whois.iana.org",
    "whois.internic.net"
  ]
}
```

### Date Format Support
The scripts support multiple date formats:
- `YYYYMMDD` (20250310)
- `YYYY-MM-DD` (2025-03-10)
- `YYYY-MM-DDTHH:MM:SSZ` (ISO format)
- And more via pandas automatic parsing

## 🛡️ Features for Security Analysis

- **High Entropy Detection**: Identifies potentially algorithmically generated domains
- **Non-Latin Character Detection**: Flags domains with suspicious character sets
- **Historical Filtering**: Excludes domains registered before 1985 (likely invalid dates)
- **Status Monitoring**: Tracks domain lifecycle states
- **Pattern Recognition**: Identifies common attack infrastructure patterns

## 📈 Visualization Features

- **Interactive Charts**: Plotly-based fullscreen visualizations
- **Responsive Design**: Charts adapt to screen size
- **Export Options**: PNG/HTML export capabilities
- **Trend Analysis**: Automatic trend line fitting
- **Statistical Annotations**: Peak detection and highlighting

## 🔧 Troubleshooting

**Common Issues:**
- **WHOIS Rate Limiting**: Adjust worker count (`-w`) or add delays
- **Invalid Dates**: Script automatically filters out unparseable dates
- **Memory Usage**: Use pickle files for large datasets
- **Network Timeouts**: Retry failed queries or use alternative servers

## 📝 License

This project is designed for educational and research purposes. Please respect WHOIS server terms of service and implement appropriate rate limiting for production use.

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional WHOIS server support
- Enhanced pattern detection algorithms
- New visualization types
- Performance optimizations
- Additional domain classification categories
