from flask import Flask, render_template, request
import pickle
import re
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import pandas as pd
import ipaddress

# Define is_ip function
def is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except:
        return False

# Load the trained phishing detection model
with open('phishing_model.pkl', 'rb') as file:
    loaded_model = pickle.load(file)

def extract_features_from_url(url):
    parsed = urlparse(url)
    domain_info = tldextract.extract(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    url_lower = url.lower()

    try:
        whois_info = whois.whois(hostname)
    except:
        whois_info = {}

    response = None
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        html_length = len(response.text)
    except:
        soup = None
        html_length = 0

    page_rank = 0
    google_index = 0
    web_traffic = 0
    statistical_report = 0
    external_favicon = 0

    try:
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days if creation_date else -1
    except:
        domain_age = -1

    try:
        expiration_date = whois_info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        domain_registration_length = (expiration_date - datetime.now()).days if expiration_date else -1
    except:
        domain_registration_length = -1

    anchors = soup.find_all('a') if soup else []
    all_links = [a.get('href') for a in anchors]
    int_links = [l for l in all_links if l and hostname in l]
    ext_links = [l for l in all_links if l and hostname not in l and "http" in l]
    media_links = [l for l in all_links if l and any(l.endswith(ext) for ext in ['.png', '.jpg', '.mp4'])]

    safe_anchor = 0
    if anchors:
        safe = [a for a in anchors if a.get('href') and '#' in a.get('href')]
        safe_anchor = len(safe) / len(anchors)

    login_form = 0
    if soup:
        forms = soup.find_all('form')
        for f in forms:
            if 'login' in str(f).lower():
                login_form = 1
                break

    phish_hints = sum([s in url_lower for s in ['secure', 'account', 'bank', 'login', 'update']])
    path_words = re.split(r'[\W_]', path)
    raw_words = re.split(r'[\W_]', url)
    host_words = re.split(r'[\W_]', hostname)

    features = {
        'google_index': google_index,
        'page_rank': page_rank,
        'nb_hyperlinks': len(all_links),
        'www': int('www' in hostname),
        'nb_qm': url.count('?'),
        'phish_hints': phish_hints,
        'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
        'web_traffic': web_traffic,
        'longest_word_path': max([len(w) for w in path_words]) if path_words else 0,
        'length_words_raw': sum([len(w) for w in raw_words]),
        'safe_anchor': safe_anchor,
        'ip': int(is_ip(hostname)),
        'domain_in_brand': int(domain_info.domain in url_lower),
        'nb_www': url_lower.count('www'),
        'nb_space': url.count(' '),
        'nb_hyphens': url.count('-'),
        'nb_eq': url.count('='),
        'php': int('.php' in url_lower),
        'net': int('.net' in hostname),
        'domain_in_title': 0,
        'shortening_service': int(any(service in url_lower for service in ['bit.ly', 'tinyurl', 'goo.gl'])),
        'shortest_word_path': min([len(w) for w in path_words]) if path_words else 0,
        'longest_words_raw': max([len(w) for w in raw_words]) if raw_words else 0,
        'domain_age': domain_age,
        'html': html_length,
        'ratio_extHyperlinks': len(ext_links) / len(all_links) if all_links else 0,
        'nb_slash': url.count('/'),
        'nb_dots': url.count('.'),
        'ratio_intHyperlinks': len(int_links) / len(all_links) if all_links else 0,
        'nb_underscore': url.count('_'),
        'ratio_digits_url': sum(c.isdigit() for c in url) / len(url),
        'org': int('.org' in hostname),
        'empty_title': int(soup.title is None or not soup.title.string.strip()) if soup else 1,
        'http': int(parsed.scheme == 'http'),
        'length_hostname': len(hostname),
        'length_url': len(url),
        'https': int(parsed.scheme == 'https'),
        'nb_percent': url.count('%'),
        'external_favicon': external_favicon,
        'avg_word_path': sum(len(w) for w in path_words) / len(path_words) if path_words else 0,
        'domain_registration_length': domain_registration_length,
        'links_in_tags': len(all_links),
        'nb_redirection': 1 if response and response.history else 0,
        'avg_word_host': sum(len(w) for w in host_words) / len(host_words) if host_words else 0,
        'char_repeat': max([url.count(c) for c in set(url)]) / len(url),
        'whois_registered_domain': int('domain_name' in whois_info and whois_info.domain_name),
        'com': int('.com' in hostname),
        'http_in_path': int('http' in path),
        'login_form': login_form,
        'prefix_suffix': int('-' in domain_info.domain),
        'longest_word_host': max([len(w) for w in host_words]) if host_words else 0,
        'nb_com': url_lower.count('.com'),
        'statistical_report': statistical_report,
        'suspecious_tld': int(any(tld in hostname for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])),
        'avg_words_raw': sum(len(w) for w in raw_words) / len(raw_words) if raw_words else 0,
        'shortest_words_raw': min([len(w) for w in raw_words]) if raw_words else 0,
        'ratio_extErrors': 0,
        'shortest_word_host': min([len(w) for w in host_words]) if host_words else 0,
        'domain_with_copyright': int('©' in response.text.lower() if response else False),
        'nb_extCSS': len([l for l in soup.find_all('link') if 'stylesheet' in str(l)]) if soup else 0,
        'ratio_intMedia': len([l for l in media_links if hostname in l]) / len(media_links) if media_links else 0,
        'ratio_extMedia': len([l for l in media_links if hostname not in l]) / len(media_links) if media_links else 0,
        'ratio_extRedirection': 0
    }

    df = pd.DataFrame([features])
    df = df[loaded_model.get_booster().feature_names]
    return df

# Initialize Flask app
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def check_url():
    if request.method == 'POST':
        url = request.form['url']
        try:
            features = extract_features_from_url(url)
            prediction = loaded_model.predict(features)[0]
            if prediction == 1:
                result = "This is a Phishing website."
            else:
                result = "This is a safe website."
        except Exception as e:
            result = f" Error processing URL: {str(e)}"
        return render_template('index.html', result=result)
    return render_template('index.html', result=None)

if __name__ == '__main__':
    app.run(debug=True)
