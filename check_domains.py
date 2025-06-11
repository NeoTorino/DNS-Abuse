import argparse
import os
import re
import json
import socket
import time
import random
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from typing import Optional, List, Dict

# Suppress noisy logging
logging.getLogger("whois.whois").setLevel(logging.CRITICAL)

# WHOIS server configurations
WHOIS_SERVERS = {}

# Counter for load balancing
server_usage_counter = {}

def load_whois_servers(config_file: str = "whois_servers.json") -> Dict:
    """Load WHOIS server configurations from JSON file"""
    global WHOIS_SERVERS
    
    # Default fallback configuration
    default_config = {
        'default': [
            "whois.iana.org",
            "whois.internic.net"
        ]
    }
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            WHOIS_SERVERS = json.load(f)
        print(f"📂 Loaded WHOIS server configuration from {config_file}")
            
        # Ensure we have at least default servers
        if 'default' not in WHOIS_SERVERS:
            WHOIS_SERVERS['default'] = default_config['default']
            
    except Exception as e:
        print(f"⚠️  Error loading WHOIS server config: {e}")
        print("Using minimal fallback configuration")
        WHOIS_SERVERS = default_config
    
    return WHOIS_SERVERS

def get_tld(domain: str) -> str:
    """Extract TLD from domain"""
    parts = domain.split('.')
    if len(parts) >= 2:
        # Handle special cases like .co.uk
        if len(parts) >= 3 and parts[-2] == 'co' and parts[-1] == 'uk':
            return 'co.uk'
        return parts[-1]
    return 'com'  # default fallback

def get_whois_servers(tld: str) -> List[str]:
    """Get available WHOIS servers for a TLD"""
    return WHOIS_SERVERS.get(tld.lower(), WHOIS_SERVERS['default'])

def select_server(tld: str) -> str:
    """Select server using round-robin load balancing"""
    servers = get_whois_servers(tld)
    
    # Initialize counter for this TLD if not exists
    if tld not in server_usage_counter:
        server_usage_counter[tld] = 0
    
    # Round-robin selection
    server = servers[server_usage_counter[tld] % len(servers)]
    server_usage_counter[tld] += 1
    
    return server

def custom_whois_query(domain: str, server: str, timeout: int = 10) -> Optional[str]:
    """Perform raw WHOIS query via socket connection"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode())
        
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        
        return response.decode(errors='ignore')
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
        # Silently handle common network errors
        return None
    except Exception as e:
        # Only print unexpected errors
        print(f"Unexpected error querying {server} for {domain}: {e}")
        return None

def determine_domain_status(response: str) -> str:
    """Determine domain status from WHOIS response"""
    if not response:
        return "nxdomain"
    
    response_lower = response.lower()
    
    # Check for non-existent domain indicators
    if any(indicator in response_lower for indicator in [
        'no match', 'not found', 'no matching record', 'no data found',
        'object does not exist', 'status: free', 'available'
    ]):
        return "nxdomain"
    
    # Check for specific statuses
    status_patterns = {
        'redemption': ['redemption period', 'redemptionperiod'],
        'pending delete': ['pending delete', 'pendingdelete'],
        'expired': ['expired', 'status: expired'],
        'suspended': ['suspended', 'hold'],
        'locked': ['locked', 'clienthold'],
        'transfer prohibited': ['transfer prohibited', 'transferprohibited'],
        'update prohibited': ['update prohibited', 'updateprohibited'],
        'delete prohibited': ['delete prohibited', 'deleteprohibited'],
    }
    
    for status, patterns in status_patterns.items():
        if any(pattern in response_lower for pattern in patterns):
            return status
    
    # If domain exists but no specific status found, assume active
    return "active"

def parse_whois_response(response: str, domain: str) -> Optional[Dict]:
    """Parse WHOIS response to extract key information"""
    if not response:
        return {
            'domain': domain,
            'name': domain.split('.')[0],
            'status': 'nxdomain',
            'registry': '',
            'registrar': '',
            'creation_date': '',
            'updated_date': '',
            'expiration_date': ''
        }
    
    # Initialize result dictionary
    result = {
        'domain': domain,
        'name': domain.split('.')[0],
        'status': determine_domain_status(response),
        'registry': '',
        'registrar': '',
        'creation_date': '',
        'updated_date': '',
        'expiration_date': ''
    }
    
    # If domain doesn't exist, return early
    if result['status'] == 'nxdomain':
        return result
    
    lines = response.lower().split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Extract registrar
        if 'registrar:' in line:
            result['registrar'] = line.split('registrar:')[1].strip()
        elif 'registrar organization:' in line:
            result['registrar'] = line.split('registrar organization:')[1].strip()
        
        # Extract creation date
        if any(x in line for x in ['creation date:', 'created:', 'registered:']):
            for prefix in ['creation date:', 'created:', 'registered:']:
                if prefix in line:
                    date_str = line.split(prefix)[1].strip()
                    result['creation_date'] = date_str.split()[0]  # Take first part
                    break
        
        # Extract updated date
        if any(x in line for x in ['updated date:', 'modified:', 'last updated:']):
            for prefix in ['updated date:', 'modified:', 'last updated:']:
                if prefix in line:
                    date_str = line.split(prefix)[1].strip()
                    result['updated_date'] = date_str.split()[0]
                    break
        
        # Extract expiration date
        if any(x in line for x in ['expiration date:', 'expires:', 'expiry date:']):
            for prefix in ['expiration date:', 'expires:', 'expiry date:']:
                if prefix in line:
                    date_str = line.split(prefix)[1].strip()
                    result['expiration_date'] = date_str.split()[0]
                    break
        
        # Extract registry
        if 'registry domain id:' in line:
            result['registry'] = 'Registry Domain ID found'
        elif 'whois server:' in line:
            result['registry'] = line.split('whois server:')[1].strip()
    
    return result

def is_domain_too_old(creation_date, cutoff_year: int = 1985) -> bool:
    """Check if domain was registered before or in the cutoff year (default: 1985)"""
    # Handle NaN values (which are float objects in pandas)
    if pd.isna(creation_date):
        return False  # Keep domains with NaN creation dates
    
    # Handle empty strings
    if not creation_date or str(creation_date).strip() == '':
        return False  # Keep domains with no creation date
    
    try:
        # Handle different date formats
        date_str = str(creation_date).strip()
        if isinstance(creation_date, list):
            date_str = str(creation_date[0]).strip()
        
        # Parse the date
        parsed_date = pd.to_datetime(date_str, errors='coerce')
        if pd.isna(parsed_date):
            return False  # Keep domains with unparseable dates
        
        # Check if year is <= cutoff year (excludes cutoff year and everything before)
        return parsed_date.year <= cutoff_year
        
    except Exception:
        return False  # Keep domains if we can't parse the date

def load_existing_domains(domains_csv_path: str) -> pd.DataFrame:
    """Load existing domains from domains.csv file"""
    if os.path.exists(domains_csv_path):
        try:
            df = pd.read_csv(domains_csv_path)
            print(f"📂 Loaded {len(df)} existing domains from {domains_csv_path}")
            return df
        except Exception as e:
            print(f"Warning: Could not load existing domains file: {e}")
            return pd.DataFrame(columns=["Domain", "Name", "Status", "Registry", "Registrar", "Created", "Updated", "Expires"])
    else:
        print(f"📝 Creating new domains file: {domains_csv_path}")
        return pd.DataFrame(columns=["Domain", "Name", "Status", "Registry", "Registrar", "Created", "Updated", "Expires"])

def save_domains_csv(df: pd.DataFrame, domains_csv_path: str):
    """Save domains DataFrame to CSV file"""
    try:
        df.to_csv(domains_csv_path, index=False, quoting=1)
        print(f"💾 Saved {len(df)} domains to {domains_csv_path}")
    except Exception as e:
        print(f"Error saving domains CSV: {e}")

def parse_domain_with_load_balancing(domain: str, existing_df: pd.DataFrame, force_check: bool = False) -> Optional[List]:
    """Parse domain using load-balanced WHOIS servers, skip if already exists unless force is True"""
    try:
        # Check if domain already exists in DataFrame and force is False
        if not force_check and not existing_df.empty and domain in existing_df['Domain'].values:
            existing_row = existing_df[existing_df['Domain'] == domain].iloc[0]
            print(f"⏭️  Skipping {domain} (already exists with status: {existing_row['Status']})")
            return None
        
        tld = get_tld(domain)
        server = select_server(tld)
        
        if force_check and not existing_df.empty and domain in existing_df['Domain'].values:
            print(f"🔄 Force checking {domain} (.{tld}) via {server}")
        else:
            print(f"🔍 Querying {domain} (.{tld}) via {server}")
        
        # Add small random delay to avoid overwhelming servers
        time.sleep(random.uniform(0.1, 0.5))
        
        response = custom_whois_query(domain, server)
        
        if not response:
            # Try fallback to default servers
            for fallback_server in WHOIS_SERVERS['default']:
                print(f"Trying fallback server {fallback_server} for {domain}")
                response = custom_whois_query(domain, fallback_server)
                if response:
                    break
        
        parsed = parse_whois_response(response, domain)
        if not parsed:
            # Create nxdomain entry
            parsed = {
                'domain': domain,
                'name': domain.split('.')[0],
                'status': 'nxdomain',
                'registry': '',
                'registrar': '',
                'creation_date': '',
                'updated_date': '',
                'expiration_date': ''
            }
        
        return [
            parsed['domain'],
            parsed['name'],
            parsed['status'],
            parsed['registry'],
            parsed['registrar'],
            parsed['creation_date'],
            parsed['updated_date'],
            parsed['expiration_date']
        ]
        
    except Exception as e:
        print(f"Error processing {domain}: {e}")
        # Return nxdomain entry for failed domains
        return [
            domain,
            domain.split('.')[0],
            'nxdomain',
            '',
            '',
            '',
            '',
            ''
        ]

def clean_domain_line(line: str) -> Optional[str]:
    """Clean and validate domain line"""
    line = line.strip()
    if line.startswith("!") or line.startswith("#") or not line:
        return None
    line = re.sub(r'^\|\|', '', line)
    line = re.sub(r'\^$', '', line)
    line = line.strip()
    
    # Basic domain validation
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
        return None
    
    return line

def create_plotly_chart(df: pd.DataFrame, output_folder: str):
    """Create beautiful Plotly chart for domain registrations over time (monthly view) - FULLSCREEN"""
    try:
        output_path = os.path.join(output_folder, "domain_registrations_chart.html")
        
        # Filter only active domains with valid creation dates for the chart
        active_df = df[df['Status'] == 'active'].copy()
        
        if active_df.empty or active_df["Created"].isnull().all():
            print("No valid creation dates found for chart generation")
            return
        
        # Clean and convert creation dates
        created_dates = active_df["Created"].apply(
            lambda x: x[0] if isinstance(x, list) else x
        )
        created_dates = pd.to_datetime(created_dates, errors='coerce', utc=True)
        created_dates = created_dates.dropna()

        if created_dates.empty:
            print("No valid dates after cleaning for chart generation")
            return

        # Convert to local timezone first, then remove timezone info for period conversion
        created_dates_local = created_dates.dt.tz_convert(None)  # Remove timezone info
        
        # Aggregate by month
        count_by_date = created_dates_local.dt.to_period("M").value_counts().sort_index()
        
        if count_by_date.empty:
            print("No data available for chart generation")
            return

        # Prepare data for plotting
        months = [str(period) for period in count_by_date.index]
        counts = count_by_date.values

        # Create figure with custom styling - FULLSCREEN CONFIGURATION
        fig = go.Figure()

        # Add gradient bar chart with hover effects
        fig.add_trace(
            go.Bar(
                x=months,
                y=counts,
                name="Domain Registrations",
                marker=dict(
                    color=counts,
                    colorscale='Viridis',  # Beautiful gradient
                    line=dict(color='rgba(50, 50, 50, 0.8)', width=1),
                    opacity=0.85
                ),
                hovertemplate="<b>%{x}</b><br>" +
                            "Domains: <b>%{y:,}</b><br>" +
                            "<extra></extra>",
                text=counts,
                textposition='outside',
                textfont=dict(size=14, color='#2C3E50')  # Larger text for fullscreen
            )
        )

        # Add trend line if we have enough data points
        if len(counts) > 1:
            # Fit linear trend line
            x_numeric = np.arange(len(counts))
            z = np.polyfit(x_numeric, counts, 1)
            p = np.poly1d(z)
            trend = p(x_numeric)

            fig.add_trace(
                go.Scatter(
                    x=months,
                    y=trend,
                    mode='lines+markers',
                    name='Trend Line',
                    line=dict(
                        color='#E74C3C',
                        width=5,  # Thicker line for fullscreen
                        dash='dash'
                    ),
                    marker=dict(
                        size=10,  # Larger markers for fullscreen
                        color='#C0392B',
                        line=dict(width=2, color='white')
                    ),
                    hovertemplate="<b>Trend</b><br>" +
                                "Month: %{x}<br>" +
                                "Projected: <b>%{y:.0f}</b><br>" +
                                "<extra></extra>"
                )
            )

        # Calculate statistics for subtitle
        total_domains = len(df)
        active_domains = len(active_df)
        avg_per_month = np.mean(counts) if len(counts) > 0 else 0
        max_month = months[np.argmax(counts)] if len(months) > 0 else "N/A"
        max_count = np.max(counts) if len(counts) > 0 else 0

        # Enhanced layout with FULLSCREEN styling
        fig.update_layout(
            title=dict(
                text=f"<b>Domain Registration Analytics</b><br>" +
                     f"<span style='font-size:20px; color:#7F8C8D'>" +  # Larger subtitle
                     f"Monthly View • {total_domains:,} Total Domains • {active_domains:,} Active • Avg: {avg_per_month:.1f}/month</span>",
                font=dict(size=32, color='#2C3E50'),  # Much larger title
                x=0.5,
                xanchor='center'
            ),
            xaxis=dict(
                title=dict(
                    text="<b>Time Period</b>",
                    font=dict(size=20, color='#34495E')  # Larger axis titles
                ),
                tickangle=45,
                tickfont=dict(size=16, color='#5D6D7E'),  # Larger tick labels
                gridcolor='rgba(189, 195, 199, 0.3)',
                gridwidth=1,
                showline=True,
                linewidth=2,
                linecolor='#BDC3C7'
            ),
            yaxis=dict(
                title=dict(
                    text="<b>Number of Domain Registrations</b>",
                    font=dict(size=20, color='#34495E')  # Larger axis titles
                ),
                tickfont=dict(size=16, color='#5D6D7E'),  # Larger tick labels
                gridcolor='rgba(189, 195, 199, 0.3)',
                gridwidth=1,
                showline=True,
                linewidth=2,
                linecolor='#BDC3C7',
                zeroline=True,
                zerolinewidth=2,
                zerolinecolor='#E5E8E8'
            ),
            plot_bgcolor='rgba(248, 249, 250, 0.8)',
            paper_bgcolor='white',
            hovermode='x unified',
            hoverlabel=dict(
                bgcolor="rgba(44, 62, 80, 0.9)",
                bordercolor="white",
                font_size=16,  # Larger hover text
                font_family="Arial"
            ),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                font=dict(size=16, color='#34495E'),  # Larger legend
                bgcolor='rgba(255, 255, 255, 0.8)',
                bordercolor='#BDC3C7',
                borderwidth=1
            ),
            margin=dict(l=100, r=100, t=150, b=100),  # Larger margins
            # FULLSCREEN DIMENSIONS - Use viewport dimensions
            width=None,   # Let it auto-size to viewport
            height=None,  # Let it auto-size to viewport
            autosize=True,  # Enable auto-sizing
            font=dict(family="Arial, sans-serif")
        )

        # Add annotations for insights with larger text
        if max_count > 0:
            fig.add_annotation(
                x=max_month,
                y=max_count,
                text=f"Peak: {max_count} domains",
                showarrow=True,
                arrowhead=2,
                arrowsize=1.5,  # Larger arrow
                arrowwidth=3,   # Thicker arrow
                arrowcolor="#E74C3C",
                ax=30,
                ay=-40,
                bgcolor="rgba(231, 76, 60, 0.1)",
                bordercolor="#E74C3C",
                borderwidth=2,
                font=dict(size=16, color="#C0392B")  # Larger annotation text
            )

        # Save as HTML with FULLSCREEN config
        config = {
            'displayModeBar': True,
            'displaylogo': False,
            'modeBarButtonsToRemove': ['pan2d', 'lasso2d', 'select2d'],
            'responsive': True,  # Make chart responsive to window size
            'toImageButtonOptions': {
                'format': 'png',
                'filename': 'domain_registrations_chart_fullscreen',
                'height': 1080,  # Full HD height
                'width': 1920,   # Full HD width
                'scale': 2
            }
        }
        
        # Create fullscreen HTML with custom CSS
        fullscreen_html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Domain Registration Analytics - Fullscreen</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            overflow-x: auto;
        }}
        .chart-container {{
            width: 100vw;
            height: 100vh;
            position: relative;
        }}
        .fullscreen-info {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255,255,255,0.9);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            color: #666;
            z-index: 1000;
        }}
    </style>
</head>
<body>
    <div class="fullscreen-info">
        🖥️ Fullscreen Mode | Press F11 for maximum viewing | Use toolbar to download chart
    </div>
    <div class="chart-container" id="chart"></div>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script>
        // The chart will be embedded here
        var config = {config};
        var layout = {fig.to_dict()['layout']};
        var data = {fig.to_dict()['data']};
        
        // Update layout for true fullscreen
        layout.width = window.innerWidth;
        layout.height = window.innerHeight;
        layout.autosize = true;
        
        Plotly.newPlot('chart', data, layout, config);
        
        // Handle window resize
        window.addEventListener('resize', function() {{
            var update = {{
                width: window.innerWidth,
                height: window.innerHeight
            }};
            Plotly.relayout('chart', update);
        }});
    </script>
</body>
</html>
"""
        
        # Write the custom fullscreen HTML
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(fullscreen_html)
            
        print(f"📊 FULLSCREEN Interactive chart saved to: {output_path}")
        
        # Try to save as high-resolution PNG
        # The Kaleido package has known compatibility issues with FreeBSD. This option has been disabled
        # Alternative use PNG generation using Selenium (if PNG is required)
        # try:
        #     png_path = os.path.join(output_folder, "domain_registrations_chart.png")
        #     fig.write_image(png_path, width=1920, height=1080, scale=3)  # Full HD resolution
        #     print(f"📊 High-resolution PNG chart saved to: {png_path}")
        # except Exception as png_error:
        #     print(f"⚠️  Could not save PNG image: {png_error}")
        #     print("💡 To enable PNG export, try installing kaleido with:")
        #     print("   conda install -c conda-forge python-kaleido")
        #     print("   or")
        #     print("   pip install kaleido==0.2.1")
        #     print("📊 HTML chart is still available and fully interactive!")
        
        # Try to show the chart
        try:
            fig.show(config=config)
            print("🚀 Opening fullscreen chart in your default browser...")
        except Exception as show_error:
            print(f"⚠️  Could not display chart in browser: {show_error}")
            print(f"📊 Open the HTML file manually for fullscreen experience: {output_path}")
        
    except Exception as e:
        print(f"Warning: Could not generate chart: {e}")
        print("📊 Chart generation failed, but data processing completed successfully.")

def save_dataframe(df: pd.DataFrame, filepath: str):
    """Save DataFrame to pickle file for later restoration"""
    try:
        df.to_pickle(filepath)
        print(f"💾 DataFrame saved to: {filepath}")
    except Exception as e:
        print(f"Error saving DataFrame: {e}")

def load_dataframe(filepath: str) -> Optional[pd.DataFrame]:
    """Load DataFrame from pickle file"""
    try:
        df = pd.read_pickle(filepath)
        print(f"📂 DataFrame loaded from: {filepath}")
        return df
    except Exception as e:
        print(f"Error loading DataFrame: {e}")
        return None

def update_dataframe_with_new_data(existing_df: pd.DataFrame, new_data: List[List]) -> pd.DataFrame:
    """Update existing DataFrame with new data, replacing existing entries or appending new ones"""
    if not new_data:
        return existing_df
    
    # Create DataFrame from new data
    new_df = pd.DataFrame(new_data, columns=[
        "Domain", "Name", "Status", "Registry", "Registrar", "Created", "Updated", "Expires"
    ])
    
    if existing_df.empty:
        return new_df
    
    # Update logic: replace existing domains, append new ones
    updated_df = existing_df.copy()
    
    for _, new_row in new_df.iterrows():
        domain = new_row['Domain']
        if domain in updated_df['Domain'].values:
            # Replace existing entry
            updated_df.loc[updated_df['Domain'] == domain] = new_row
            print(f"🔄 Updated existing entry for {domain}")
        else:
            # Append new entry
            updated_df = pd.concat([updated_df, new_row.to_frame().T], ignore_index=True)
            print(f"➕ Added new entry for {domain}")
    
    return updated_df

def main():
    parser = argparse.ArgumentParser(description="Check domain registration with load-balanced WHOIS queries.")
    parser.add_argument("-i", "--input", help="Path to input file containing domains")
    parser.add_argument("-o", "--output", default="output", help="Output folder path (default: 'output')")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads (default: 5)")
    parser.add_argument("-l", "--limit", type=int, help="Limit number of domains to process (default: 1000)")
    parser.add_argument("-r", "--restore", help="Path to saved DataFrame pickle file to restore from")
    parser.add_argument("-f", "--force", action="store_true", help="Force check domains even if they exist in results")
    args = parser.parse_args()

    # Ensure output directory exists
    output_folder = args.output
    os.makedirs(output_folder, exist_ok=True)
    print(f"📁 Output folder: {output_folder}")
    
    # Load WHOIS server configuration
    load_whois_servers()

    # Define paths
    domains_csv_path = os.path.join(output_folder, "domains.csv")
    pickle_output = os.path.join(output_folder, "data_frame.pkl")

    # Check if we're in restore mode
    if args.restore:
        print(f"🔄 Restoring from saved DataFrame: {args.restore}")
        df = load_dataframe(args.restore)
        if df is None:
            print("❌ Failed to load DataFrame. Exiting.")
            return
        
        print(f"✅ Loaded {len(df)} domains from saved DataFrame")
        
        # Generate fullscreen chart from restored data
        create_plotly_chart(df, output_folder)
        
        # Save to domains.csv in the output folder
        save_domains_csv(df, domains_csv_path)
        return

    # Normal processing mode - require input
    if not args.input:
        parser.error("Input file (-i) is required when not using restore mode (-r)")

    # Load existing domains from domains.csv (not results.csv)
    existing_df = load_existing_domains(domains_csv_path)

    with open(args.input, "r", encoding="utf-8") as file:
        raw_lines = file.readlines()

    domains = []
    for line in raw_lines:
        cleaned = clean_domain_line(line)
        if cleaned:
            domains.append(cleaned)

    random.shuffle(domains)

    # Limit domains to process
    domains = domains[:args.limit]
    print(f"🔍 Checking {len(domains)} domains with {args.workers} workers...")
    print("📊 Available WHOIS servers by TLD:")
    for tld, servers in WHOIS_SERVERS.items():
        print(f"  .{tld}: {len(servers)} servers")

    new_domain_data = []
    processed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Pass force_check parameter to the worker function
        future_to_domain = {
            executor.submit(parse_domain_with_load_balancing, domain, existing_df, args.force): domain 
            for domain in domains
        }

        for future in as_completed(future_to_domain):
            processed += 1
            info = future.result()
            if info:
                new_domain_data.append(info)

            # Progress indicator
            if processed % 50 == 0:
                print(f"Progress: {processed}/{len(domains)} domains processed")

    # Update existing DataFrame with new data
    if new_domain_data:
        updated_df = update_dataframe_with_new_data(existing_df, new_domain_data)
    else:
        updated_df = existing_df

    # Filter out domains registered before/in 1985
    print(f"📅 Filtering out domains registered before/in January 1985...")
    original_count = len(updated_df)
    updated_df = updated_df[~updated_df['Created'].apply(is_domain_too_old)]
    filtered_count = original_count - len(updated_df)
    if filtered_count > 0:
        print(f"🗑️  Excluded {filtered_count} domains registered before/in 1985")

    # Save updated domains to CSV in output folder
    save_domains_csv(updated_df, domains_csv_path)
    
    # Save DataFrame pickle
    save_dataframe(updated_df, pickle_output)

    print(f"✅ All {len(updated_df)} domains (including NXDOMAIN) saved to: {domains_csv_path}")
    print(f"💾 DataFrame saved to: {pickle_output}")
    
    # Print statistics
    status_counts = updated_df['Status'].value_counts()
    print(f"\n📊 Domain status summary:")
    for status, count in status_counts.items():
        print(f"  {status}: {count}")
    
    # Print server usage statistics
    print(f"\n📈 Server usage statistics:")
    for tld, count in server_usage_counter.items():
        servers = get_whois_servers(tld)
        print(f"  .{tld}: {count} queries across {len(servers)} servers")

    # Generate fullscreen Plotly chart
    create_plotly_chart(updated_df, output_folder)

if __name__ == "__main__":
    main()