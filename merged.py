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
import pandas as pd
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logging Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# HTTP Headers
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/91.0.4472.124 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ──────────────────────────────────────────────────────────────────────────
# Compass Scraping Functions
# ──────────────────────────────────────────────────────────────────────────

def extract_numeric(text):
    """Extract numeric value from text string"""
    try:
        m = re.findall(r"[\d,.]+", text or "")
        return float(m[0].replace(",", "")) if m else None
    except (ValueError, IndexError):
        return None

def norm_field(field):
    """Normalize field to ensure consistent structure"""
    if isinstance(field, list) and field:
        return field[0] if isinstance(field[0], dict) else {}
    if isinstance(field, dict):
        return field
    return {}

def extract_year_built(soup):
    """Extract year built from soup"""
    try:
        lbl = soup.find("span", {"data-tn":"uc-listing-buildingInfo"}, string="Year Built")
        if lbl:
            s = lbl.find_next_sibling("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_bedrooms(soup, prop):
    """Extract bedroom count"""
    try:
        # Try property data first
        b = prop.get("numberOfRooms") or prop.get("numberOfBedrooms")
        if b:
            return b
        
        # Try soup parsing
        lbl = soup.find("span", string="Beds")
        if lbl:
            s = lbl.find_next_sibling("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_bathrooms(soup, prop):
    """Extract bathroom count"""
    try:
        # Try soup parsing first
        lbl = soup.find("span", string="Baths")
        if lbl:
            s = lbl.find_next_sibling("strong")
            if s:
                return s.get_text(strip=True)
        
        # Fallback to property data
        return prop.get("numberOfBathroomsTotal") or prop.get("numberOfBathrooms")
    except Exception:
        pass
    return None

def extract_square_footage(soup, prop):
    """Extract square footage"""
    try:
        # Try property data first
        floor_size = norm_field(prop.get("floorSize", {}))
        v = floor_size.get("value")
        if v:
            return v
        
        # Try soup parsing
        lbl = soup.find("span", string=re.compile(r"Sq\.?\s*Ft", re.IGNORECASE))
        if lbl:
            s = lbl.find_next("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_lot_size(soup):
    """Extract lot size"""
    try:
        lbl = soup.find("span", string=re.compile(r"Lot Size", re.IGNORECASE))
        if lbl:
            s = lbl.find_next("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_listing_update(soup):
    """Extract listing update date"""
    try:
        span = soup.select_one("span.lastUpdatedDate-text")
        if span:
            return span.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_listing_agent(soup, prop):
    """Extract listing agent"""
    try:
        elem = soup.find(string=re.compile(r"Listing Courtesy of", re.IGNORECASE))
        if elem and "of" in elem:
            return elem.split("of", 1)[1].strip()
        
        # Fallback to property data
        seller = prop.get("seller", {})
        if isinstance(seller, dict):
            return seller.get("name")
    except Exception:
        pass
    return None

def extract_property_tax_pin(soup):
    """Extract property tax PIN/APN"""
    try:
        lbl = soup.find("span", string=re.compile(r"\bAPN\b", re.IGNORECASE))
        if lbl:
            s = lbl.find_next_sibling("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_address_components(soup, prop):
    """Extract address components"""
    try:
        a = prop.get("address", {}) or {}
        res = {
            "street": a.get("streetAddress"),
            "city": a.get("addressLocality"),
            "state": a.get("addressRegion"),
            "zip": a.get("postalCode")
        }
        
        # If not all components found, try parsing from H1
        if not all(res.values()):
            h1 = soup.find("h1")
            if h1:
                m = re.search(r"(.*?),\s*(.*?),\s*([A-Z]{2})\s*(\d{5})?", h1.get_text())
                if m:
                    street, city, st, zp = m.groups()
                    res.update({
                        k: res[k] or v for k, v in 
                        zip(["street", "city", "state", "zip"], [street, city, st, zp])
                    })
        
        return res
    except Exception:
        return {"street": None, "city": None, "state": None, "zip": None}

def extract_property_type(soup, prop):
    """Extract property type"""
    try:
        t = prop.get("@type")
        if t:
            return t
        
        lbl = soup.find("span", string=re.compile(r"Property\s+Type", re.IGNORECASE))
        if lbl:
            s = lbl.find_next("strong")
            if s:
                return s.get_text(strip=True)
    except Exception:
        pass
    return None

def extract_property_taxes(soup):
    """Extract property taxes"""
    try:
        row = soup.find("th", string=re.compile(r"Taxes", re.IGNORECASE))
        if row:
            td = row.find_next_sibling("td")
            if td:
                return td.get_text(strip=True)
        
        # Alternative method
        lbl = soup.find(string=re.compile(r"Taxes:", re.IGNORECASE))
        if lbl:
            return lbl.split(":", 1)[1].strip()
    except Exception:
        pass
    return None

def extract_list_section(soup, header_regex):
    """Extract list sections like amenities"""
    try:
        header = soup.find(re.compile("^h[2-4]$"), string=re.compile(header_regex, re.IGNORECASE))
        if not header:
            return []
        
        ul = header.find_next_sibling("ul") or header.find_next("ul")
        if ul:
            return [li.get_text(strip=True) for li in ul.find_all("li")]
    except Exception:
        pass
    return []

def extract_description(soup):
    """Extract property description"""
    try:
        div = soup.find("div", class_=re.compile(r"description", re.IGNORECASE))
        if div:
            return div.get_text("\n", strip=True)
        
        sec = soup.find("section", id=re.compile(r"description", re.IGNORECASE))
        if sec:
            return sec.get_text("\n", strip=True)
    except Exception:
        pass
    return None

def scrape_compass_listing(url):
    """Main scraping function for Compass listings"""
    logger.info(f"Scraping URL: {url}")
    
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # JSON-LD extraction
        prop = {}
        for tag in soup.find_all("script", {"type": "application/ld+json"}):
            try:
                data = json.loads(tag.string)
                raw = data.get("@graph", data if isinstance(data, list) else [data])
                for node in raw:
                    if isinstance(node, dict) and "Residence" in str(node.get("@type", "")):
                        prop = node
                        break
                if prop:
                    break
            except Exception:
                continue

        # Next.js hydration fallback
        if not prop:
            nt = soup.find("script", {"id": "__NEXT_DATA__"})
            if nt:
                try:
                    nd = json.loads(nt.string)
                    prop = nd.get("props", {}).get("pageProps", {}).get("listing", {}) or {}
                except Exception as e:
                    logger.warning(f"Couldn't parse __NEXT_DATA__: {e}")

        # Extract all data
        address = extract_address_components(soup, prop)
        offers = norm_field(prop.get("offers", {}))
        
        # Price extraction
        price_info = {"formatted": "", "numeric": None}
        if offers.get("price"):
            currency = offers.get('priceCurrency', '')
            price = offers.get('price', '')
            price_info = {
                "formatted": f"{currency} {price}".strip(),
                "numeric": extract_numeric(str(price))
            }

        result = {
            "address": address,
            "price": price_info,
            "bedrooms": extract_bedrooms(soup, prop),
            "bathrooms": extract_bathrooms(soup, prop),
            "square_footage": extract_square_footage(soup, prop),
            "lot_size": extract_lot_size(soup),
            "year_built": extract_year_built(soup) or prop.get("yearBuilt"),
            "listing_update": extract_listing_update(soup),
            "property_type": extract_property_type(soup, prop),
            "listing_agent": extract_listing_agent(soup, prop),
            "property_tax_pin": extract_property_tax_pin(soup),
            "source_url": url,
            "taxes": extract_property_taxes(soup),
            "amenities": extract_list_section(soup, r"(Amenities|Features)"),
            "description": extract_description(soup),
            "building_info": extract_list_section(soup, r"Building Information"),
        }

        return result
        
    except Exception as e:
        logger.error(f"Error scraping {url}: {e}")
        raise

# ──────────────────────────────────────────────────────────────────────────
# DocuSign Functions
# ──────────────────────────────────────────────────────────────────────────

def fix_private_key_format(private_key_str):
    """Fix private key formatting for JWT"""
    if not private_key_str:
        return None
    
    key = private_key_str.strip()
    
    if "-----BEGIN RSA PRIVATE KEY-----" in key and "\n" not in key:
        key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----\n")
        key = key.replace("-----END RSA PRIVATE KEY-----", "\n-----END RSA PRIVATE KEY-----")
        
        lines = key.split('\n')
        if len(lines) >= 2:
            header = lines[0]
            footer = lines[-1]
            body = ''.join(lines[1:-1])
            
            formatted_body = '\n'.join([body[i:i+64] for i in range(0, len(body), 64)])
            key = f"{header}\n{formatted_body}\n{footer}"
    
    return key

def create_jwt_assertion():
    """Create JWT assertion for DocuSign authentication"""
    integration_key = os.getenv("DS_INTEGRATION_KEY")
    user_id = os.getenv("DS_USER_ID")
    private_key_raw = os.getenv("DS_PRIVATE_KEY")
    
    if not all([integration_key, user_id, private_key_raw]):
        raise ValueError("Missing required DocuSign environment variables")
    
    private_key = fix_private_key_format(private_key_raw)
    
    if not private_key or not private_key.strip().startswith("-----BEGIN"):
        raise ValueError("DS_PRIVATE_KEY missing or not PEM-formatted in env")
    
    now = int(time())
    payload = {
        "iss": integration_key,
        "sub": user_id,
        "aud": "account-d.docusign.com",
        "iat": now,
        "exp": now + 3600,
        "scope": "signature impersonation"
    }
    
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        logger.error(f"JWT encoding failed: {e}")
        raise ValueError(f"Could not encode JWT: {e}")

def get_user_info(access_token):
    """Get DocuSign user information"""
    try:
        resp = requests.get(
            "https://account-d.docusign.com/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.error(f"Failed to get user info: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return None

def request_access_token():
    """Request access token from DocuSign"""
    assertion = create_jwt_assertion()
    resp = requests.post(
        "https://account-d.docusign.com/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion
        }
    )
    if resp.status_code != 200:
        logger.error(f"Token request failed: {resp.status_code} {resp.text}")
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}")
    
    return resp.json()["access_token"]

def flatten_data_for_docusign(data):
    """Flatten nested data structure for DocuSign templates"""
    flattened = {}
    
    def flatten_dict(obj, parent_key=''):
        if not isinstance(obj, dict):
            return
            
        for key, value in obj.items():
            new_key = f"{parent_key}_{key}" if parent_key else key
            
            if isinstance(value, dict):
                flatten_dict(value, new_key)
            elif isinstance(value, list):
                if value:
                    flattened[new_key] = ", ".join(str(item) for item in value)
                else:
                    flattened[new_key] = ""
            elif value is not None:
                flattened[new_key] = str(value)
            else:
                flattened[new_key] = ""
    
    flatten_dict(data)
    return flattened

def send_envelope(data, signer_email, signer_name, template_id):
    """Send envelope to DocuSign"""
    token = request_access_token()
    
    # Get user info for account details
    user_info = get_user_info(token)
    if not user_info:
        raise RuntimeError("Could not get user info")
    
    # Find default account
    default_acct = None
    for acc in user_info["accounts"]:
        if acc.get("is_default"):
            default_acct = acc
            break
    
    if not default_acct:
        default_acct = user_info["accounts"][0]  # Use first account as fallback
    
    account_id = default_acct["account_id"]
    base_uri = default_acct["base_uri"]
    
    # Prepare tabs
    text_tabs = []
    checkbox_tabs = []
    
    for key, value in data.items():
        if key.lower().startswith("checkbox_"):
            checkbox_tabs.append({
                "tabLabel": key,
                "selected": "true" if str(value).strip().lower() in ["yes", "true", "1", "y"] else "false"
            })
        else:
            str_value = str(value) if value is not None else ""
            if len(str_value) > 500:
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
            "roleName": os.getenv("DS_ROLE_NAME", "Signer 1"),
            "tabs": {
                "textTabs": text_tabs,
                "checkboxTabs": checkbox_tabs
            }
        }]
    }
    
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
        raise RuntimeError(f"DocuSign envelope creation failed: {resp.status_code} - {resp.text}")

# ──────────────────────────────────────────────────────────────────────────
# Streamlit UI - VERTICAL CENTERED LAYOUT
# ──────────────────────────────────────────────────────────────────────────

# Set page config
st.set_page_config(
    page_title="Compass & CSV to DocuSign", 
    page_icon="🏠",
    layout="centered"  # Changed from "wide" to "centered"
)

# Add custom CSS for centering and spacing
st.markdown("""
<style>
    .main-container {
        max-width: 800px;
        margin: 0 auto;
        padding: 2rem;
    }
    
    .stButton > button {
        width: 100%;
        margin: 0.5rem 0;
    }
    
    .centered-content {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 1rem;
    }
    
    .section-spacing {
        margin: 2rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Main container
with st.container():
    # Main title - centered
    st.markdown("<div class='centered-content'>", unsafe_allow_html=True)
    st.title("🏠 Compass & CSV to DocuSign")
    st.markdown("*Automate your real estate document workflow*")
    st.markdown("</div>", unsafe_allow_html=True)

# Initialize session state
if "listing_data" not in st.session_state:
    st.session_state["listing_data"] = None
if "csv_data" not in st.session_state:
    st.session_state["csv_data"] = None

st.markdown("<div class='section-spacing'>", unsafe_allow_html=True)

# DocuSign Connection Test - Vertical Layout
st.header("🔧 DocuSign Connection Test")

# Test Connection Button - Full width
if st.button("Test Connection", type="secondary", key="test_connection"):
    with st.spinner("Testing DocuSign connection..."):
        try:
            token = request_access_token()
            user_info = get_user_info(token)
            if user_info:
                st.success("✅ DocuSign connection successful!")
                st.session_state["docusign_connected"] = True
            else:
                st.error("❌ Could not retrieve user info")
                st.session_state["docusign_connected"] = False
        except Exception as e:
            st.error(f"❌ Connection failed: {str(e)}")
            st.session_state["docusign_connected"] = False

# Status message below button
if st.session_state.get("docusign_connected"):
    st.info("DocuSign is ready to use")
else:
    st.warning("Test DocuSign connection before proceeding")

st.markdown("</div>", unsafe_allow_html=True)
st.divider()

# Compass Listing Section - Vertical Layout
st.header("🏘️ Compass Listing Scraper")

# URL Input - Full width
compass_url = st.text_input(
    "Enter Compass Listing URL",
    placeholder="https://www.compass.com/listing/...",
    key="compass_url_input"
)

# Scrape Button - Full width
if st.button("Scrape Listing", key="scrape_compass", type="primary"):
    if not compass_url:
        st.error("Please enter a URL")
    elif not re.match(r"https?://", compass_url):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        with st.spinner("Scraping listing data..."):
            try:
                listing_data = scrape_compass_listing(compass_url)
                st.session_state["listing_data"] = listing_data
                st.success("✅ Listing scraped successfully!")
                
                # Display key info
                if listing_data.get("address"):
                    addr = listing_data["address"]
                    st.write(f"**Address:** {addr.get('street', '')}, {addr.get('city', '')}, {addr.get('state', '')} {addr.get('zip', '')}")
                
                if listing_data.get("price", {}).get("formatted"):
                    st.write(f"**Price:** {listing_data['price']['formatted']}")
                
                bed_bath = []
                if listing_data.get("bedrooms"):
                    bed_bath.append(f"{listing_data['bedrooms']} bed")
                if listing_data.get("bathrooms"):
                    bed_bath.append(f"{listing_data['bathrooms']} bath")
                if bed_bath:
                    st.write(f"**Details:** {', '.join(bed_bath)}")
                
            except Exception as e:
                st.error(f"Error scraping listing: {str(e)}")
                logger.error(f"Scraping error: {e}")

# Display scraped data status
if st.session_state["listing_data"]:
    st.success("✅ Listing data ready")
    if st.checkbox("Show raw listing data"):
        st.json(st.session_state["listing_data"])

st.divider()

# CSV Data Handler Section - Vertical Layout
st.header("📊 CSV Data Handler")

# CSV File Upload - Full width
csv_file = st.file_uploader(
    "Upload CSV File", 
    type=["csv"], 
    key="csv_upload"
)

# Preview Checkbox - Full width
show_preview = st.checkbox("Show Preview", key="show_csv_preview")

# Process CSV file
if csv_file is not None:
    try:
        with st.spinner("Loading CSV..."):
            df = pd.read_csv(csv_file)
            st.session_state["csv_data"] = df
            st.success(f"✅ {len(df)} rows loaded from {csv_file.name}")
            
    except Exception as e:
        st.error(f"Error reading CSV: {str(e)}")

# Row selection and preview
if st.session_state["csv_data"] is not None:
    df = st.session_state["csv_data"]
    
    # Row selector - Full width
    selected_row_idx = st.selectbox(
        "Select Row to Use", 
        range(len(df)),
        format_func=lambda x: f"Row {x + 1}: {str(df.iloc[x, 0])[:50]}..." if len(df.columns) > 0 else f"Row {x + 1}",
        key="row_selector"
    )
    
    selected_row = df.iloc[selected_row_idx].to_dict()
    st.success("✅ CSV row selected")
    
    # Compact preview
    if show_preview:
        st.write("**Selected Row Data:**")
        # Show data in a more compact format
        preview_data = {k: (str(v)[:50] + "..." if len(str(v)) > 50 else str(v)) for k, v in selected_row.items()}
        st.json(preview_data)

st.divider()

# DocuSign Sending Section - Vertical Layout
st.header("📧 Send Combined Data to DocuSign")

# Recipient Email - Full width
signer_email = st.text_input(
    "Recipient Email", 
    value="matthew.kelly@onmail.com",
    key="signer_email"
)

# Recipient Name - Full width
signer_name = st.text_input(
    "Recipient Name", 
    value="Matthew Kelly",
    key="signer_name"
)

# Send button - Full width
send_envelope_btn = st.button("📤 Send Envelope", type="primary", key="send_envelope")

# Send logic
if send_envelope_btn:
    if not signer_email or not signer_name:
        st.error("Please provide both recipient email and name.")
    elif not st.session_state["listing_data"] or st.session_state["csv_data"] is None:
        st.error("Please provide both Compass listing and CSV data.")
    else:
        with st.spinner("Preparing and sending envelope..."):
            try:
                # Combine listing and CSV data
                listing_flat = flatten_data_for_docusign(st.session_state["listing_data"])
                df = st.session_state["csv_data"]
                csv_row = df.iloc[selected_row_idx].to_dict()
                
                # Merge data with prefixes to avoid conflicts
                final_data = {}
                for k, v in listing_flat.items():
                    final_data[f"listing_{k}"] = v
                for k, v in csv_row.items():
                    final_data[f"client_{k}"] = v
                
                # Use single template ID from environment variable
                template_id = os.getenv("DS_TEMPLATE_ID")
                
                if not template_id:
                    st.error("Template ID not configured. Please set DS_TEMPLATE_ID in environment variables.")
                    st.stop()
                
                # Show data preview
                with st.expander("📋 Data Preview (Click to expand)"):
                    st.json(final_data)
                    st.write(f"**Template ID:** {template_id}")
                    st.write(f"**Total fields:** {len(final_data)}")
                
                # Send envelope
                env_id = send_envelope(final_data, signer_email, signer_name, template_id)
                st.success(f"✅ Envelope sent successfully!")
                st.info(f"**Envelope ID:** {env_id}")
                st.balloons()
                
            except Exception as e:
                st.error(f"❌ Error sending envelope: {str(e)}")
                logger.error(f"DocuSign envelope error: {e}")
                
                # Show detailed error in expander
                with st.expander("Error Details"):
                    st.code(str(e))

# Footer
st.divider()
st.markdown("""
<div style='text-align: center; color: #666; font-size: 0.9em; margin-top: 2rem;'>
    <p>🏠 Compass & CSV to DocuSign Integration</p>
    <p>Streamlining real estate document workflows</p>
</div>
""", unsafe_allow_html=True)