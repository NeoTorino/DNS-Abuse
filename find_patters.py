# Required libraries
import pandas as pd
import argparse
from datetime import datetime
from collections import Counter
import tldextract
import difflib
from wordcloud import WordCloud
import plotly.express as px
import plotly.io as pio
import os
import re
import string
import math
from nltk.corpus import words
import nltk

# Download required NLTK data
try:
    nltk.data.find('corpora/words')
except LookupError:
    nltk.download('words')

# Ensure default renderer is for notebook or static image
pio.renderers.default = "svg"

def is_english_word(word):
    """Check if a word exists in English dictionary"""
    english_words = set(words.words())
    return word.lower() in english_words

def calculate_entropy(text):
    """Calculate entropy of a string to detect random-like strings"""
    if not text:
        return 0
    
    # Count frequency of each character
    freq = Counter(text.lower())
    length = len(text)
    
    # Calculate entropy
    entropy = 0
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    
    return entropy

def is_high_entropy(text, threshold=3.5):
    """Determine if text has high entropy (likely random)"""
    return calculate_entropy(text) > threshold

def contains_non_latin_chars(text):
    """Check if text contains non-Latin characters"""
    latin_pattern = re.compile(r'^[a-zA-Z0-9\-_.]+$')
    return not bool(latin_pattern.match(text))

def clean_domain_name(domain):
    """Extract base domain and clean it for analysis"""
    # Extract domain without TLD
    ext = tldextract.extract(domain)
    
    # Combine subdomain and domain parts
    parts = []
    if ext.subdomain:
        parts.append(ext.subdomain)
    if ext.domain:
        parts.append(ext.domain)
    
    full_domain = '.'.join(parts)
    
    # Replace separators with spaces and clean
    cleaned = re.sub(r'[._-]+', ' ', full_domain)
    cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    
    return cleaned

def classify_domain_topic(domain_text):
    """Classify domain into topics based on content analysis"""
    if not domain_text:
        return "empty"
    
    # Check for non-Latin characters
    if contains_non_latin_chars(domain_text):
        return "non-english"
    
    # Split into words
    words_list = domain_text.lower().split()
    
    if not words_list:
        return "empty"
    
    # Check if all words are high entropy (random-like)
    high_entropy_count = sum(1 for word in words_list if is_high_entropy(word))
    if high_entropy_count == len(words_list):
        return "high-entropy"
    
    # Check English words
    english_word_count = sum(1 for word in words_list if is_english_word(word))
    
    # Classify based on English word ratio
    english_ratio = english_word_count / len(words_list)
    
    if english_ratio >= 0.7:
        return "english"
    elif english_ratio > 0.3:
        return "mixed-english"
    else:
        return "non-english-words"

def parse_date_flexible(date_str):
    """Parse date string with multiple format support"""
    if pd.isna(date_str) or date_str == '' or date_str is None:
        return None
    
    # Convert to string and clean
    date_str = str(date_str).strip()
    if not date_str:
        return None
    
    # List of date formats to try
    date_formats = [
        '%Y%m%d',                    # 20250310, 20170106
        '%Y-%m-%d',                  # 1987-05-14, 2017-11-18
        '%Y-%m-%dt%H:%M:%Sz',       # 2025-06-10t08:12:27z
        '%Y-%m-%dt%H:%M:%S.%fz',    # 2025-02-08t23:09:35.223z
        '%Y-%m-%dt%H:%M:%sz',       # 2007-12-17t19:49:27z (lowercase)
        '%Y-%m-%dT%H:%M:%SZ',       # ISO format with uppercase
        '%Y-%m-%dT%H:%M:%S.%fZ',    # ISO format with microseconds
    ]
    
    # Try each format
    for fmt in date_formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            # Remove timezone info if present to ensure naive datetime
            return parsed_date.replace(tzinfo=None)
        except ValueError:
            continue
    
    # If none of the specific formats work, try pandas built-in parser
    try:
        parsed = pd.to_datetime(date_str, errors='coerce')
        if pd.notna(parsed):
            # Convert to naive datetime (remove timezone info)
            parsed_dt = parsed.to_pydatetime()
            if parsed_dt.tzinfo is not None:
                parsed_dt = parsed_dt.replace(tzinfo=None)
            return parsed_dt
    except:
        pass
    
    return None

def load_and_filter_data(filepath, from_date=None, to_date=None, status=None, return_df=False):
    """Load CSV data and apply filters - ONLY ACCEPT DOMAINS WITH VALID DATES"""
    df = pd.read_csv(filepath)

    # Clean column names
    df.columns = [col.strip().lower() for col in df.columns]

    # Map column names (handle variations)
    domain_col = None
    created_col = None
    status_col = None
    
    for col in df.columns:
        if 'domain' in col:
            domain_col = col
        elif 'created' in col:
            created_col = col
        elif 'status' in col:
            status_col = col
    
    if domain_col is None:
        # Assume first column is domain
        domain_col = df.columns[0]

    print(f"Found columns: domain='{domain_col}', created='{created_col}', status='{status_col}'")
    print(f"Total domains in CSV: {len(df)}")

    # Parse dates and filter to only valid dates from the start
    if created_col:
        print("Parsing creation dates...")
        df['parsed_created'] = df[created_col].apply(parse_date_flexible)
        
        # Count and show initial date parsing stats
        valid_dates_count = df['parsed_created'].notna().sum()
        invalid_dates_count = df['parsed_created'].isna().sum()
        
        print(f"Domains with valid creation dates: {valid_dates_count}")
        print(f"Domains with invalid/unparseable dates: {invalid_dates_count}")
        
        # FILTER TO ONLY DOMAINS WITH VALID DATES
        original_count = len(df)
        df = df[df['parsed_created'].notna()]
        filtered_out = original_count - len(df)
        
        print(f"*** FILTERED OUT {filtered_out} domains with invalid dates ***")
        print(f"*** CONTINUING WITH ONLY {len(df)} domains with valid dates ***")
        
        if len(df) > 0:
            # Show date range
            min_date = df['parsed_created'].min()
            max_date = df['parsed_created'].max()
            print(f"Date range: {min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}")
            
            # Show some examples of parsed dates
            sample_parsed = df[['parsed_created']].head()
            print("Sample parsed dates:")
            for idx, row in sample_parsed.iterrows():
                print(f"  {row['parsed_created']}")
        else:
            print("ERROR: No domains with valid dates found!")
            return [] if not return_df else pd.DataFrame()

    # Date filtering - now all domains have valid dates
    if from_date and created_col and len(df) > 0:
        from_dt = datetime.strptime(from_date, '%Y-%m-%d')
        original_count = len(df)
        
        domains_before = (df['parsed_created'] < from_dt).sum()
        domains_from_onwards = (df['parsed_created'] >= from_dt).sum()
        
        print(f"Domains before {from_date}: {domains_before}")
        print(f"Domains from {from_date} onwards: {domains_from_onwards}")
        
        df = df[df['parsed_created'] >= from_dt]
        filtered_count = original_count - len(df)
        print(f"Domains filtered out by 'from' date: {filtered_count}")
        print(f"Domains remaining after 'from' date filter: {len(df)}")
    
    # Apply to_date filter
    if to_date and created_col and len(df) > 0:
        to_dt = datetime.strptime(to_date, '%Y-%m-%d')
        original_count = len(df)
        
        df = df[df['parsed_created'] <= to_dt]
        filtered_count = original_count - len(df)
        print(f"Domains filtered out by 'to' date: {filtered_count}")
        print(f"Domains remaining after 'to' date filter: {len(df)}")

    # Status filtering
    if status and status_col and len(df) > 0:
        original_count = len(df)
        df = df[df[status_col].str.lower() == status.lower()]
        print(f"Domains after status filter ('{status}'): {len(df)} (filtered out {original_count - len(df)})")

    if len(df) == 0:
        print("WARNING: No domains remain after filtering!")
        return [] if not return_df else pd.DataFrame()

    if return_df:
        return df
    else:
        return df[domain_col].dropna().tolist()

def create_monthly_plot(df, output_dir):
    """Create a plotly chart showing domains created per month"""
    if len(df) == 0:
        print("No data available for plotting")
        return
    
    # All domains in df should have valid creation dates now
    if 'parsed_created' not in df.columns or df['parsed_created'].isna().all():
        print("No domains with valid creation dates found for plotting")
        return
    
    # Extract year-month for grouping
    df['year_month'] = df['parsed_created'].dt.to_period('M')
    
    # Count domains per month
    monthly_counts = df['year_month'].value_counts().sort_index()
    
    if len(monthly_counts) == 0:
        print("No monthly data available for plotting")
        return
    
    # Convert to DataFrame for plotting
    plot_data = pd.DataFrame({
        'Month': [str(period) for period in monthly_counts.index],
        'Domain Count': monthly_counts.values
    })
    
    # Create the plot
    fig = px.line(plot_data, 
                  x='Month', 
                  y='Domain Count',
                  title=f'Domains Created Per Month (Total: {len(df)} domains)',
                  markers=True)
    
    # Customize the plot
    fig.update_layout(
        xaxis_title="Month",
        yaxis_title="Number of Domains",
        xaxis=dict(tickangle=45),
        showlegend=False,
        height=500
    )
    
    # Save as HTML
    plot_path = os.path.join(output_dir, "domains_per_month.html")
    fig.write_html(plot_path)
    print(f"Monthly domains plot saved to {plot_path}")
    
    # Display summary stats
    print(f"Monthly breakdown:")
    for month, count in monthly_counts.items():
        print(f"  {month}: {count} domains")
    
    # Open the plot in a web browser
    import webbrowser
    try:
        # Try to open with specific browsers first
        browsers = ['firefox', 'chrome', 'chromium', 'safari']
        opened = False
        
        for browser_name in browsers:
            try:
                browser = webbrowser.get(browser_name)
                browser.open(f'file://{os.path.abspath(plot_path)}')
                print(f"Opening plot in {browser_name}...")
                opened = True
                break
            except webbrowser.Error:
                continue
        
        if not opened:
            # Fall back to default
            webbrowser.open(f'file://{os.path.abspath(plot_path)}')
            print(f"Opening plot in default browser...")
            
    except Exception as e:
        print(f"Could not open browser automatically: {e}")
        print(f"Please manually open: {os.path.abspath(plot_path)}")

def extract_words_and_topics(domains):
    """Extract words and classify domains into topics"""
    all_words = []
    topics = []
    domain_classifications = {}
    
    for domain in domains:
        cleaned = clean_domain_name(domain)
        topic = classify_domain_topic(cleaned)
        
        domain_classifications[domain] = {
            'cleaned': cleaned,
            'topic': topic
        }
        
        topics.append(topic)
        
        # Add words for word cloud (only from English and mixed domains)
        if topic in ['english', 'mixed-english']:
            words_in_domain = cleaned.lower().split()
            # Filter out very short words and add only English words
            valid_words = [word for word in words_in_domain 
                          if len(word) > 2 and is_english_word(word)]
            all_words.extend(valid_words)
    
    return all_words, topics, domain_classifications

def find_common_patterns(domain_classifications, min_len=4):
    """Find common patterns in domains"""
    patterns = set()
    
    # Group domains by topic
    topic_groups = {}
    for domain, info in domain_classifications.items():
        topic = info['topic']
        if topic not in topic_groups:
            topic_groups[topic] = []
        topic_groups[topic].append(info['cleaned'])
    
    # Find patterns within each topic group
    for topic, cleaned_domains in topic_groups.items():
        if len(cleaned_domains) < 2:
            continue
            
        # Find common substrings
        for i, dom1 in enumerate(cleaned_domains):
            for dom2 in cleaned_domains[i+1:]:
                seq = difflib.SequenceMatcher(None, dom1, dom2)
                match = seq.find_longest_match(0, len(dom1), 0, len(dom2))
                if match.size >= min_len:
                    substr = dom1[match.a: match.a + match.size].strip()
                    if len(substr) >= min_len:
                        patterns.add(f"{topic}: {substr}")
    
    return patterns, topic_groups

def generate_wordcloud(words, output_dir):
    """Generate word cloud from words"""
    if not words:
        print("No words available for word cloud generation")
        return
    
    freq = Counter(words)
    
    # Filter out very common words that might not be informative
    common_words = {'com', 'www', 'http', 'https', 'org', 'net', 'edu'}
    filtered_freq = {word: count for word, count in freq.items() 
                    if word not in common_words and len(word) > 2}
    
    if not filtered_freq:
        print("No meaningful words for word cloud after filtering")
        return
    
    wc = WordCloud(width=800, height=400, background_color='white', 
                   max_words=100).generate_from_frequencies(filtered_freq)
    
    # Save as PNG
    wc.to_file(os.path.join(output_dir, "wordcloud.png"))
    print(f"Word cloud saved to {os.path.join(output_dir, 'wordcloud.png')}")

def save_patterns_and_topics(patterns, topic_groups, output_file, total_domains):
    """Save patterns and topic analysis to file"""
    with open(output_file, 'w') as f:
        f.write("=== DOMAIN TOPIC ANALYSIS ===\n")
        f.write(f"(Analysis based on {total_domains} domains with valid creation dates)\n\n")
        
        # Write topic summary
        f.write("Topic Distribution:\n")
        for topic, domains in topic_groups.items():
            f.write(f"  {topic}: {len(domains)} domains\n")
        f.write("\n")
        
        # Write patterns
        f.write("=== IDENTIFIED PATTERNS ===\n\n")
        if patterns:
            for pattern in sorted(patterns):
                f.write(f"{pattern}\n")
        else:
            f.write("No common patterns found.\n")
        
        f.write("\n=== DETAILED TOPIC BREAKDOWN ===\n\n")
        for topic, domains in topic_groups.items():
            f.write(f"{topic.upper()} ({len(domains)} domains):\n")
            for domain in sorted(domains)[:20]:  # Limit to first 20 for readability
                f.write(f"  - {domain}\n")
            if len(domains) > 20:
                f.write(f"  ... and {len(domains) - 20} more\n")
            f.write("\n")

def main():
    parser = argparse.ArgumentParser(description="Identify domain name patterns and topics (valid dates only).")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file path")
    parser.add_argument("-o", "--output", required=True, help="Output TXT file path for patterns")
    parser.add_argument("-f", "--from", dest="from_date", 
                       help="Filter domains registered after this date (YYYY-MM-DD)")
    parser.add_argument("-t", "--to", dest="to_date", 
                       help="Filter domains registered before this date (YYYY-MM-DD)")
    parser.add_argument("-s", "--status", dest="status", 
                       help="Filter domains with specific status")
    parser.add_argument("-p", "--plot", action="store_true",
                       help="Generate plot showing domains created per month")
    
    args = parser.parse_args()

    try:
        print("Loading and filtering data (valid dates only)...")
        print("=" * 60)
        
        # Always load the full DataFrame to get consistent results
        df = load_and_filter_data(args.input, args.from_date, args.to_date, args.status, return_df=True)
        
        if len(df) == 0:
            print("No domains remaining after filtering. Exiting.")
            return 1
        
        # Extract domains list from the DataFrame
        domain_col = None
        for col in df.columns:
            if 'domain' in col:
                domain_col = col
                break
        if domain_col is None:
            domain_col = df.columns[0]
        
        domains = df[domain_col].dropna().tolist()
        
        print("=" * 60)
        print(f"FINAL DATASET: {len(domains)} domains with valid dates")
        print("=" * 60)
        
        # Generate plot if requested
        if args.plot:
            print("Creating monthly domains plot...")
            output_dir = os.path.dirname(args.output) or '.'
            create_monthly_plot(df, output_dir)
            print()
        
        print("Extracting words and analyzing topics...")
        words, topics, domain_classifications = extract_words_and_topics(domains)
        
        print("Finding common patterns...")
        patterns, topic_groups = find_common_patterns(domain_classifications)
        
        print("Saving analysis results...")
        save_patterns_and_topics(patterns, topic_groups, args.output, len(domains))
        
        print("Generating word cloud...")
        output_dir = os.path.dirname(args.output) or '.'
        generate_wordcloud(words, output_dir)
        
        print(f"\nAnalysis complete! Results saved to {args.output}")
        print(f"Total domains analyzed: {len(domains)}")
        print(f"Topic distribution: {dict(Counter(topics))}")
        print(f"Common patterns found: {len(patterns)}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    main()