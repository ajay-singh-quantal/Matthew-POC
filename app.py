import os
import re
import json
import urllib.parse
import logging
from datetime import datetime
from time import time
import requests
from bs4 import BeautifulSoup
import jwt
import streamlit as st
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# --- HTTP Headers ---
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ──────────────────────────────────────────────────────────────────────────
# Compass scraping helpers (original logic restored)
# ──────────────────────────────────────────────────────────────────────────

def get_listing_url_via_api(mls):
    api_url = f"https://www.compass.com/api/v1/mls/{mls}"
    resp = requests.get(api_url, headers=HEADERS, timeout=10)
    if resp.status_code == 200:
        try:
            return resp.json().get("url")
        except ValueError:
            logger.warning("MLS API returned invalid JSON")
    else:
        logger.warning(f"MLS API error: {resp.status_code}")
    return None


def search_compass_listings(mls=None, address=None):
    term = mls or address
    if not term:
        raise ValueError("Provide MLS or address")
    search_url = f"https://www.compass.com/search/listings/?q={urllib.parse.quote(term)}"
    resp       = requests.get(search_url, headers=HEADERS, timeout=15)
    soup       = BeautifulSoup(resp.text, "html.parser")
    if a := soup.find("a", href=re.compile(r"^/listing/")):
        return "https://www.compass.com" + a["href"]
    return None


def validate_mls_number(val):
    if not val:
        return False
    cleaned = re.sub(r"[^A-Za-z0-9]","", val.strip())
    return 4 <= len(cleaned) <= 15


def find_listing_url_via_google(mls):
    query      = f"{mls} compass listing"
    google_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
    resp       = requests.get(google_url, headers=HEADERS, timeout=10)
    soup       = BeautifulSoup(resp.text, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/url?q="):
            href = urllib.parse.unquote(href.split("/url?q=")[1].split("&")[0])
        if "compass.com/listing/" in href:
            return href
    return None


def extract_numeric(text):
    m = re.findall(r"[\d,.]+", text or "")
    return float(m[0].replace(",", "")) if m else None


def norm_field(field):
    if isinstance(field, list) and field:
        return field[0] if isinstance(field[0], dict) else {}
    if isinstance(field, dict):
        return field
    return {}


def extract_year_built(soup):
    lbl = soup.find("span", {"data-tn":"uc-listing-buildingInfo"}, string="Year Built")
    if lbl and (s := lbl.find_next_sibling("strong")):
        return s.get_text(strip=True)
    return None


def extract_bedrooms(soup, prop):
    if (b := prop.get("numberOfRooms") or prop.get("numberOfBedrooms")):
        return b
    if lbl := soup.find("span", string="Beds"):
        if (s := lbl.find_next_sibling("strong")):
            return s.get_text(strip=True)
    return None


def extract_bathrooms(soup, prop):
    if lbl := soup.find("span", string="Baths"):
        if (s := lbl.find_next_sibling("strong")):
            return s.get_text(strip=True)
    return prop.get("numberOfBathroomsTotal") or prop.get("numberOfBathrooms")


def extract_square_footage(soup, prop):
    if (v := norm_field(prop.get("floorSize", {})).get("value")):
        return v
    if lbl := soup.find("span", string=re.compile(r"Sq\.?\s*Ft", re.IGNORECASE)):
        if (s := lbl.find_next("strong")):
            return s.get_text(strip=True)
    return None


def extract_lot_size(soup):
    if lbl := soup.find("span", string=re.compile(r"Lot Size", re.IGNORECASE)):
        if (s := lbl.find_next("strong")):
            return s.get_text(strip=True)
    return None


def extract_listing_update(soup):
    if span := soup.select_one("span.lastUpdatedDate-text"):
        return span.get_text(strip=True)
    return None


def extract_listing_agent(soup, prop):
    if elem := soup.find(string=re.compile(r"Listing Courtesy of", re.IGNORECASE)):
        if "of" in elem:
            return elem.split("of",1)[1].strip()
    return prop.get("seller", {}).get("name")


def extract_property_tax_pin(soup):
    if lbl := soup.find("span", string=re.compile(r"\bAPN\b", re.IGNORECASE)):
        if (s := lbl.find_next_sibling("strong")):
            return s.get_text(strip=True)
    return None


def extract_address_components(soup, prop):
    a = prop.get("address", {}) or {}
    res = {"street":a.get("streetAddress"),"city":a.get("addressLocality"),"state":a.get("addressRegion"),"zip":a.get("postalCode")}
    if not all(res.values()):
        if h1 := soup.find("h1"):
            m = re.search(r"(.*?),\s*(.*?),\s*([A-Z]{2})\s*(\d{5})?", h1.get_text())
            if m:
                street,city,st,zp = m.groups()
                res.update({k:res[k] or v for k,v in zip(["street","city","state","zip"],[street,city,st,zp])})
    return res


def extract_property_type(soup, prop):
    if t := prop.get("@type"):
        return t
    if lbl := soup.find("span", string=re.compile(r"Property\s+Type", re.IGNORECASE)):
        if (s := lbl.find_next("strong")):
            return s.get_text(strip=True)
    return None


def extract_property_taxes(soup):
    if row := soup.find("th", string=re.compile(r"Taxes", re.IGNORECASE)):
        if td := row.find_next_sibling("td"):
            return td.get_text(strip=True)
    if lbl := soup.find(string=re.compile(r"Taxes:", re.IGNORECASE)):
        return lbl.split(":",1)[1].strip()
    return None


def extract_list_section(soup, header_regex):
    header = soup.find(re.compile("^h[2-4]$"), string=re.compile(header_regex, re.IGNORECASE))
    if not header:
        return []
    ul = header.find_next_sibling("ul") or header.find_next("ul")
    return [li.get_text(strip=True) for li in (ul.find_all("li") if ul else [])]


def extract_description(soup):
    if div := soup.find("div", class_=re.compile(r"description", re.IGNORECASE)):
        return div.get_text("\n", strip=True)
    if sec := soup.find("section", id=re.compile(r"description", re.IGNORECASE)):
        return sec.get_text("\n", strip=True)
    return None


def scrape_compass_via_jsonld(url):
    logger.info(f"Scraping URL: {url}")
    resp = requests.get(url, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    # JSON-LD pass
    prop = {}
    for tag in soup.find_all("script",{"type":"application/ld+json"}):
        try:
            data = json.loads(tag.string)
        except:
            continue
        raw = data.get("@graph", data if isinstance(data,list) else [data])
        for node in raw:
            if isinstance(node,dict) and "Residence" in str(node.get("@type","")):
                prop = node
                break
        if prop:
            break

    # Next.js hydration fallback
    if not prop and (nt := soup.find("script",{"id":"__NEXT_DATA__"})):
        try:
            nd = json.loads(nt.string)
            prop = nd["props"]["pageProps"].get("listing",{}) or {}
        except Exception as e:
            logger.warning(f"Couldn't parse __NEXT_DATA__: {e}")

    address = extract_address_components(soup, prop)
    offers  = norm_field(prop.get("offers",{}))
    price   = ({"formatted":f"{offers.get('priceCurrency','')} {offers.get('price','')}".strip(),"numeric":extract_numeric(str(offers.get("price","")))}
               if offers.get("price") else {"formatted":"","numeric":None})

    result = {
        "address":address,
        "price":price,
        "bedrooms":extract_bedrooms(soup,prop),
        "bathrooms":extract_bathrooms(soup,prop),
        "square_footage":extract_square_footage(soup,prop),
        "lot_size":extract_lot_size(soup),
        "year_built":extract_year_built(soup) or prop.get("yearBuilt"),
        "listing_update":extract_listing_update(soup),
        "property_type":extract_property_type(soup,prop),
        "listing_agent":extract_listing_agent(soup,prop),
        "mls_number":prop.get("identifier",{}).get("value"),
        "property_tax_pin":extract_property_tax_pin(soup),
        "source_url":url,
        "taxes":extract_property_taxes(soup),
        "amenities":extract_list_section(soup,r"(Amenities|Features)"),
        "description":extract_description(soup),
        "building_info":extract_list_section(soup,r"Building Information"),
    }

    if not result["mls_number"]:
        for tr in soup.find_all("tr"):
            th,td = tr.find("th"), tr.find("td")
            if th and td and re.search(r"MLS[#\s]*",th.get_text(),re.IGNORECASE):
                result["mls_number"] = td.get_text(strip=True)
                break

    return result

# ──────────────────────────────────────────────────────────────────────────
# DocuSign helpers (config hidden via env)
# ──────────────────────────────────────────────────────────────────────────

def fix_private_key_format(private_key_str):
    """Fix private key formatting issues from environment variables"""
    if not private_key_str:
        return None
    
    # Remove any extra whitespace
    key = private_key_str.strip()
    
    # If the key doesn't have proper line breaks, add them
    if "-----BEGIN RSA PRIVATE KEY-----" in key and "\n" not in key:
        # Split on the headers and reconstruct with proper formatting
        key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n")
        key = key.replace("-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----")
        
        # Add line breaks every 64 characters in the key body
        lines = key.split('\n')
        if len(lines) >= 2:
            header = lines[0]
            footer = lines[-1]
            body = ''.join(lines[1:-1])
            
            # Split body into 64-character lines
            formatted_body = '\n'.join([body[i:i+64] for i in range(0, len(body), 64)])
            key = f"{header}\n{formatted_body}\n{footer}"
    
    return key

def create_jwt_assertion():
    integration_key = os.getenv("DS_INTEGRATION_KEY")
    user_id = os.getenv("DS_USER_ID")
    private_key_raw = os.getenv("DS_PRIVATE_KEY")
    
    if not all([integration_key, user_id, private_key_raw]):
        raise ValueError("Missing required DocuSign environment variables")
    
    # Fix the private key formatting
    private_key = fix_private_key_format(private_key_raw)
    
    if not private_key or not private_key.strip().startswith("-----BEGIN"):
        raise ValueError("DS_PRIVATE_KEY missing or not PEM-formatted in env")
    
    now = int(time())
    payload = {
        "iss": integration_key,
        "sub": user_id,
        "aud": "account-d.docusign.com",  # Use demo environment
        "iat": now,
        "exp": now + 3600,
        "scope": "signature impersonation"
    }
    
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        logger.error(f"JWT encoding failed: {e}")
        logger.error(f"Private key starts with: {private_key[:50]}...")
        raise ValueError(f"Could not encode JWT: {e}")


def get_user_info(access_token):
    """Get user account information to find the correct account ID"""
    resp = requests.get(
        "https://account-d.docusign.com/oauth/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    if resp.status_code == 200:
        return resp.json()
    else:
        logger.error(f"Failed to get user info: {resp.status_code} {resp.text}")
        return None


def request_access_token(assertion):
    resp = requests.post(
        "https://account-d.docusign.com/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
              "assertion": assertion}
    )
    if resp.status_code != 200:
        logger.error(f"Token request failed: {resp.status_code} {resp.text}")
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}")
    
    token_data = resp.json()
    access_token = token_data["access_token"]
    
    # Get user info to validate account
    user_info = get_user_info(access_token)
    if user_info:
        logger.info(f"User info: {user_info}")
        accounts = user_info.get("accounts", [])
        if accounts:
            logger.info(f"Available accounts: {[acc.get('account_id') for acc in accounts]}")
    
    return access_token


def flatten_data_for_docusign(data):
    """Flatten complex data structure for DocuSign text tabs"""
    flattened = {}
    
    def flatten_dict(obj, parent_key=''):
        for key, value in obj.items():
            new_key = f"{parent_key}_{key}" if parent_key else key
            
            if isinstance(value, dict):
                flatten_dict(value, new_key)
            elif isinstance(value, list):
                if value:  # Only process non-empty lists
                    flattened[new_key] = ", ".join(str(item) for item in value)
                else:
                    flattened[new_key] = ""
            elif value is not None:
                flattened[new_key] = str(value)
            else:
                flattened[new_key] = ""
    
    flatten_dict(data)
    return flattened


def send_envelope(property_data, signer_email, signer_name):
    token = request_access_token(create_jwt_assertion())
    base_uri = os.getenv("DS_BASE_URI", "https://demo.docusign.net")
    account_id = os.getenv("DS_ACCOUNT_ID")
    template_id = os.getenv("DS_TEMPLATE_ID")
    role_name = os.getenv("DS_ROLE_NAME", "Signer 1")

    # Flatten the property data for DocuSign
    flat_data = flatten_data_for_docusign(property_data)
    
    # Create text tabs with proper validation
    text_tabs = []
    for key, value in flat_data.items():
        # Ensure value is a string and not too long (DocuSign has limits)
        str_value = str(value) if value is not None else ""
        if len(str_value) > 500:  # Truncate very long values
            str_value = str_value[:497] + "..."
        
        text_tabs.append({
            "tabLabel": key,
            "value": str_value
        })
    
    envelope = {
        "status": "sent",
        "templateId": template_id,
        "templateRoles": [{
            "email": signer_email,
            "name": signer_name,
            "roleName": role_name,
            "tabs": {"textTabs": text_tabs}
        }]
    }
    
    # Log the envelope structure for debugging
    logger.info(f"Sending envelope with {len(text_tabs)} text tabs")
    logger.debug(f"Envelope structure: {json.dumps(envelope, indent=2)}")
    
    url = f"{base_uri}/restapi/v2.1/accounts/{account_id}/envelopes"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    try:
        resp = requests.post(url, headers=headers, json=envelope)
        if resp.status_code != 201:
            logger.error(f"DocuSign API Error: {resp.status_code}")
            logger.error(f"Response: {resp.text}")
            resp.raise_for_status()
        return resp.json()["envelopeId"]
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        logger.error(f"Response content: {resp.text}")
        raise RuntimeError(f"DocuSign envelope creation failed: {resp.status_code} - {resp.text}")

# ──────────────────────────────────────────────────────────────────────────
# Streamlit UI
# ──────────────────────────────────────────────────────────────────────────

st.title("Compass to DocuSign")

# Add a debug section to Streamlit
st.header("🔧 DocuSign Configuration Debug")
if st.button("Test DocuSign Connection"):
    try:
        # Test JWT creation
        assertion = create_jwt_assertion()
        st.success("✅ JWT assertion created successfully")
        
        # Test token request
        token = request_access_token(assertion)
        st.success("✅ Access token obtained successfully")
        
        # Show configuration
        with st.expander("Current Configuration"):
            st.write(f"Integration Key: {os.getenv('DS_INTEGRATION_KEY')}")
            st.write(f"User ID: {os.getenv('DS_USER_ID')}")
            st.write(f"Account ID: {os.getenv('DS_ACCOUNT_ID')}")
            st.write(f"Base URI: {os.getenv('DS_BASE_URI')}")
            st.write(f"Template ID: {os.getenv('DS_TEMPLATE_ID')}")
            st.write(f"Role Name: {os.getenv('DS_ROLE_NAME')}")
        
    except Exception as e:
        st.error(f"❌ DocuSign connection failed: {e}")

st.divider()

# Step 1: Scrape Compass Listing
st.header("1. Scrape Compass Listing")
term = st.text_input("Enter Compass URL, MLS #, or Address")
if st.button("Scrape"):
    if term:
        try:
            url = term if re.match(r"https?://", term) else get_listing_url_via_api(term) or search_compass_listings(term)
            if not url:
                st.error("Listing not found.")
            else:
                data = scrape_compass_via_jsonld(url)
                st.json(data)
                st.session_state["flat_data"] = data
        except Exception as e:
            st.error(f"Error scraping listing: {e}")

# Step 2: Send via DocuSign (no config inputs)
st.header("2. Send via DocuSign")
signer_email = st.text_input("Signer Email")
signer_name = st.text_input("Signer Name")
if st.button("Send Envelope"):
    flat = st.session_state.get("flat_data")
    if not flat:
        st.error("Please scrape a listing first.")
    elif not signer_email or not signer_name:
        st.error("Please provide both signer email and name.")
    else:
        try:
            # Show the flattened data that will be sent
            with st.expander("Data to be sent to DocuSign"):
                flattened = flatten_data_for_docusign(flat)
                st.json(flattened)
            
            env_id = send_envelope(flat, signer_email, signer_name)
            st.success(f"Envelope sent! ID: {env_id}")
        except Exception as e:
            st.error(f"Error: {e}")
            logger.error(f"DocuSign error: {e}")