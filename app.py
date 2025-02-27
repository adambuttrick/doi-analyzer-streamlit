import re
import time
import json
import logging
import socket
import ipaddress
import requests
import pandas as pd
import streamlit as st
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

st.set_page_config(page_title="DOI Analyzer", page_icon="🔍", layout="wide")
st.title("DOI Analyzer")
st.markdown("Analyze DOIs to discover information about registration agencies, publishers, and hosting details.")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('doi_analyzer')

def create_robust_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 503, 504, 429),
    timeout=10
):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.timeout = timeout
    return session

session = create_robust_session()

def validate_doi(doi):
    doi_pattern = r'^10\.\d{4,}(\.\d+)*\/[a-zA-Z0-9\.\-\_\(\)\[\]\+\:\;\<\>\\\/@]+$'
    return bool(re.match(doi_pattern, doi))

def clean_doi(doi):
    if not doi:
        return None
    doi = doi.strip()
    if doi.startswith('https://doi.org/'):
        doi = doi[16:]
    elif doi.startswith('http://doi.org/'):
        doi = doi[15:]
    elif doi.startswith('doi:'):
        doi = doi[4:]
    return doi

def safe_request(url, method='get', allow_redirects=True, **kwargs):
    try:
        request_method = getattr(session, method.lower())
        response = request_method(
            url, allow_redirects=allow_redirects, **kwargs)
        return response, None
    except requests.exceptions.RequestException as e:
        error_message = f"Request error for {url}: {str(e)}"
        logger.error(error_message)
        return None, error_message
    except Exception as e:
        error_message = f"Unexpected error for {url}: {str(e)}"
        logger.error(error_message)
        return None, error_message

def get_ip_geolocation(ip_address):
    if not ip_address:
        return {"error": "No IP address provided"}
    response, error = safe_request(f"https://ipinfo.io/{ip_address}/json")
    if error:
        return {"error": error}
    if response and response.status_code == 200:
        return response.json()
    else:
        status_code = response.status_code if response else "No response"
        return {"error": f"Failed to get geolocation data, status code: {status_code}"}

def get_registration_agency(doi):
    if not doi:
        logger.error("No DOI provided to get_registration_agency")
        return None
    response, error = safe_request(f"https://doi.org/ra/{doi}")
    if error:
        logger.error(f"Error querying registration agency: {error}")
        return None
    if response and response.status_code == 200:
        try:
            data = response.json()
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                return data[0].get('RA')
        except ValueError as e:
            logger.error(f"Failed to parse JSON from RA API: {str(e)}")
        return None
    else:
        status_code = response.status_code if response else "No response"
        logger.error(f"Failed to get registration agency, status code: {status_code}")
        return None

def get_doi_prefix(doi):
    if not doi:
        return None
    match = re.match(r'^(10\.\d+)/', doi)
    if match:
        return match.group(1)
    return None

def get_crossref_member_by_prefix(doi_prefix):
    if not doi_prefix:
        logger.error("No DOI prefix provided to get_crossref_member_by_prefix")
        return None
    response, error = safe_request(f"https://api.crossref.org/prefixes/{doi_prefix}")
    if error:
        logger.error(f"Error querying Crossref by prefix: {error}")
        return None
    if response and response.status_code == 200:
        try:
            data = response.json()
            if 'message' in data and 'member' in data['message']:
                member_url = data['message']['member']
                member_id_match = re.search(r'/member/(\d+)$', member_url)
                if member_id_match:
                    member_id = member_id_match.group(1)
                    logger.info(f"Found member ID {member_id} from prefix lookup")
                    return get_crossref_member_info(member_id)
                else:
                    logger.warning(f"Could not extract member ID from URL: {member_url}")
            else:
                logger.warning("No member information found in prefix response")
        except ValueError as e:
            logger.error(f"Failed to parse JSON from Crossref prefix API: {str(e)}")
    else:
        status_code = response.status_code if response else "No response"
        logger.error(f"Failed to get prefix info, status code: {status_code}")
    return None

def get_datacite_prefix_info(doi_prefix):
    if not doi_prefix:
        logger.error("No DOI prefix provided to get_datacite_prefix_info")
        return {"error": "No DOI prefix provided"}
    response, error = safe_request(f"https://api.datacite.org/prefixes/{doi_prefix}")
    if error:
        return {"error": error}
    if response and response.status_code == 200:
        try:
            data = response.json()
            logger.info(f"Successfully retrieved DataCite prefix information for {doi_prefix}")
            return data
        except ValueError as e:
            error_message = f"Failed to parse JSON from DataCite prefix API: {str(e)}"
            logger.error(error_message)
            return {"error": error_message}
    else:
        status_code = response.status_code if response else "No response"
        error_message = f"Failed to get DataCite prefix info, status code: {status_code}"
        logger.error(error_message)
        return {"error": error_message}

def get_datacite_provider_from_prefix(prefix_info):
    if not prefix_info or not isinstance(prefix_info, dict):
        logger.error("Invalid prefix_info provided to get_datacite_provider_from_prefix")
        return None
    try:
        if 'data' in prefix_info and 'relationships' in prefix_info['data']:
            relationships = prefix_info['data']['relationships']
            if 'providers' in relationships and 'data' in relationships['providers']:
                providers_data = relationships['providers']['data']
                if providers_data and len(providers_data) > 0 and 'id' in providers_data[0]:
                    provider_id = providers_data[0]['id']
                    logger.info(f"Found provider ID {provider_id} from prefix relationships")
                    return provider_id
        logger.warning("No provider information found in prefix data")
        return None
    except Exception as e:
        logger.error(f"Error extracting provider from prefix: {e}")
        return None

def get_crossref_member_info(member_id):
    if not member_id:
        logger.error("No member ID provided to get_crossref_member_info")
        return {"error": "No member ID provided"}
    logger.info(f"Fetching Crossref member info for ID: {member_id}")
    response, error = safe_request(f"https://api.crossref.org/members/{member_id}")
    if error:
        return {"error": error}
    if response and response.status_code == 200:
        try:
            return response.json()['message']
        except (ValueError, KeyError) as e:
            error_message = f"Failed to parse JSON from Crossref member API: {str(e)}"
            logger.error(error_message)
            return {"error": error_message}
    else:
        status_code = response.status_code if response else "No response"
        error_message = f"Failed to get member info, status code: {status_code}"
        logger.error(error_message)
        return {"error": error_message}

def get_datacite_provider_info(provider_id):
    if not provider_id:
        logger.error("No provider ID provided to get_datacite_provider_info")
        return {"error": "No provider ID provided"}
    logger.info(f"Fetching DataCite provider info for ID: {provider_id}")
    response, error = safe_request(f"https://api.datacite.org/providers/{provider_id}")
    if error:
        return {"error": error}
    if response and response.status_code == 200:
        try:
            return response.json()
        except ValueError as e:
            error_message = f"Failed to parse JSON from DataCite provider API: {str(e)}"
            logger.error(error_message)
            return {"error": error_message}
    else:
        status_code = response.status_code if response else "No response"
        error_message = f"Failed to get provider info, status code: {status_code}"
        logger.error(error_message)
        return {"error": error_message}

def extract_crossref_location(member_info):
    location_info = {}
    if not isinstance(member_info, dict) or 'error' in member_info:
        return location_info
    if 'location' in member_info:
        location_info['address'] = member_info['location']
    if 'country' in member_info:
        location_info['country'] = member_info['country']
    if 'names' in member_info and member_info['names']:
        location_info['organization_names'] = member_info['names']
    return location_info

def extract_datacite_location(provider_info):
    location_info = {}
    if not isinstance(provider_info, dict) or 'data' not in provider_info:
        return location_info
    if 'attributes' in provider_info['data']:
        attrs = provider_info['data']['attributes']
        if 'country' in attrs:
            location_info['country'] = attrs['country']
        if 'region' in attrs:
            location_info['region'] = attrs['region']
        if 'name' in attrs:
            location_info['organization_name'] = attrs['name']
        if 'rorId' in attrs:
            location_info['ror_id'] = attrs['rorId']
        if 'website' in attrs:
            location_info['website'] = attrs['website']
    return location_info

def get_doi_info(doi):
    doi = clean_doi(doi)
    if not doi:
        return {
            'error': True,
            'message': 'No DOI provided or invalid DOI format'
        }
    if not validate_doi(doi):
        return {
            'error': True,
            'message': f'Invalid DOI format: {doi}'
        }
    result = {
        'doi': doi,
        'registration_agency': None,
        'registrant': None,
        'registrant_location': None,
        'member_info': None,
        'target_url': None,
        'final_url': None,
        'host_info': None,
        'server_geolocation': None,
        'debug_info': {
            'member_lookup_method': None,
            'member_id': None,
            'provider_id': None,
            'doi_prefix': None,
            'lookup_attempts': [],
            'errors': []
        }
    }
    doi_prefix = get_doi_prefix(doi)
    result['debug_info']['doi_prefix'] = doi_prefix
    ra_name = get_registration_agency(doi)
    if ra_name:
        result['registration_agency'] = ra_name
    else:
        result['debug_info']['errors'].append("Failed to determine registration agency")
    if result['registration_agency'] == 'Crossref':
        crossref_url = f"https://api.crossref.org/works/{doi}"
        response, error = safe_request(crossref_url)
        if error:
            result['debug_info']['errors'].append(f"Crossref API error: {error}")
        if response and response.status_code == 200:
            try:
                data = response.json()
                message = data.get('message', {})
                result['registrant'] = message.get('publisher')
                member_info = None
                member_id = None
                if 'member' in message:
                    result['debug_info']['lookup_attempts'].append("work_metadata")
                    member_url = message.get('member')
                    logger.info(f"Found member URL: {member_url}")
                    member_id_match = re.search(r'/members/(\d+)$', member_url)
                    if member_id_match:
                        member_id = member_id_match.group(1)
                        result['debug_info']['member_id'] = member_id
                        result['debug_info']['member_lookup_method'] = 'direct_from_work'
                        member_info = get_crossref_member_info(member_id)
                    else:
                        logger.warning(f"No member ID found in URL: {member_url}")
                if not member_info or 'error' in member_info:
                    if doi_prefix:
                        result['debug_info']['lookup_attempts'].append("prefix_lookup")
                        logger.info(f"Trying prefix-based lookup for {doi_prefix}")
                        member_info = get_crossref_member_by_prefix(doi_prefix)
                        if member_info and 'error' not in member_info:
                            result['debug_info']['member_lookup_method'] = 'prefix_lookup'
                            if 'id' in member_info:
                                result['debug_info']['member_id'] = member_info['id']
                if member_info and 'error' not in member_info:
                    result['member_info'] = member_info
                    result['registrant_location'] = extract_crossref_location(member_info)
                    logger.info(f"Successfully retrieved member info with method: {result['debug_info']['member_lookup_method']}")
                else:
                    logger.warning("Failed to retrieve valid member information")
                    if member_info and 'error' in member_info:
                        result['debug_info']['errors'].append(f"Member info error: {member_info['error']}")
            except Exception as e:
                error_message = f"Error processing Crossref data: {str(e)}"
                logger.error(error_message)
                result['debug_info']['errors'].append(error_message)
        elif response:
            result['debug_info']['errors'].append(f"Crossref API returned status code: {response.status_code}")
    elif result['registration_agency'] == 'DataCite':
        datacite_url = f"https://api.datacite.org/dois/{doi}"
        response, error = safe_request(datacite_url)
        if error:
            result['debug_info']['errors'].append(f"DataCite API error: {error}")
        if response and response.status_code == 200:
            try:
                result['debug_info']['lookup_attempts'].append("datacite_doi_lookup")
                logger.info(f"Querying DataCite DOI API for {doi}")
                data = response.json()
                if 'data' in data:
                    attributes = data['data'].get('attributes', {})
                    result['registrant'] = attributes.get('publisher')
                    provider_id = None
                    if 'clientId' in attributes:
                        result['debug_info']['lookup_attempts'].append("client_id_lookup")
                        client_id = attributes['clientId']
                        logger.info(f"Found client ID: {client_id}")
                        if '.' in client_id:
                            provider_id = client_id.split('.')[0]
                            result['debug_info']['provider_id'] = provider_id
                            result['debug_info']['member_lookup_method'] = 'client_id'
                            logger.info(f"Extracted provider ID {provider_id} from client ID")
                    if not provider_id and 'relationships' in data['data']:
                        result['debug_info']['lookup_attempts'].append("relationships_lookup")
                        relationships = data['data']['relationships']
                        if 'provider' in relationships and 'data' in relationships['provider']:
                            provider_data = relationships['provider']['data']
                            if provider_data and 'id' in provider_data:
                                provider_id = provider_data['id']
                                result['debug_info']['provider_id'] = provider_id
                                result['debug_info']['member_lookup_method'] = 'doi_relationships'
                                logger.info(f"Found provider ID {provider_id} from DOI relationships")
                    if provider_id:
                        provider_info = get_datacite_provider_info(provider_id)
                        if 'error' not in provider_info:
                            result['member_info'] = provider_info
                            result['registrant_location'] = extract_datacite_location(provider_info)
                        else:
                            result['debug_info']['errors'].append(f"Provider info error: {provider_info['error']}")
            except Exception as e:
                error_message = f"Error processing DataCite data: {str(e)}"
                logger.error(error_message)
                result['debug_info']['errors'].append(error_message)
        elif response:
            result['debug_info']['errors'].append(f"DataCite API returned status code: {response.status_code}")
        if not result['member_info'] and doi_prefix:
            result['debug_info']['lookup_attempts'].append("datacite_prefix_lookup")
            logger.info(f"Trying DataCite prefix lookup for {doi_prefix}")
            prefix_info = get_datacite_prefix_info(doi_prefix)
            if 'error' not in prefix_info:
                provider_id = get_datacite_provider_from_prefix(prefix_info)
                if provider_id:
                    result['debug_info']['provider_id'] = provider_id
                    result['debug_info']['member_lookup_method'] = 'prefix_lookup'
                    provider_info = get_datacite_provider_info(provider_id)
                    if 'error' not in provider_info:
                        result['member_info'] = provider_info
                        result['registrant_location'] = extract_datacite_location(provider_info)
                    else:
                        result['debug_info']['errors'].append(f"Provider info error: {provider_info['error']}")
                else:
                    result['debug_info']['errors'].append("No provider ID found in prefix information")
            else:
                result['debug_info']['errors'].append(f"Prefix info error: {prefix_info['error']}")
    resolver_url = f"https://doi.org/{doi}"
    response, error = safe_request(resolver_url, allow_redirects=False)
    if error:
        result['debug_info']['errors'].append(f"DOI resolution error: {error}")
    if response and response.status_code in [301, 302, 303, 307, 308]:
        result['target_url'] = response.headers.get('Location')
        final_response, final_error = safe_request(resolver_url, allow_redirects=True)
        if final_error:
            result['debug_info']['errors'].append(f"DOI final resolution error: {final_error}")
        if final_response:
            result['final_url'] = final_response.url
            if result['final_url']:
                try:
                    parsed_url = urlparse(result['final_url'])
                    hostname = parsed_url.netloc
                    try:
                        ip_address = socket.gethostbyname(hostname)
                        ip_obj = ipaddress.ip_address(ip_address)
                        if not ip_obj.is_private:
                            geolocation = get_ip_geolocation(ip_address)
                            if 'error' not in geolocation:
                                result['server_geolocation'] = geolocation
                            else:
                                result['debug_info']['errors'].append(f"Geolocation error: {geolocation['error']}")
                        try:
                            host_info = socket.gethostbyaddr(ip_address)
                            result['host_info'] = {
                                'hostname': hostname,
                                'ip_address': ip_address,
                                'canonical_name': host_info[0],
                                'aliases': host_info[1]
                            }
                        except socket.herror:
                            result['host_info'] = {
                                'hostname': hostname,
                                'ip_address': ip_address
                            }
                    except socket.gaierror as e:
                        result['host_info'] = {
                            'hostname': hostname,
                            'error': f'Could not resolve hostname: {str(e)}'
                        }
                        result['debug_info']['errors'].append(f"Hostname resolution error: {str(e)}")
                except Exception as e:
                    error_message = f"Error processing URL: {str(e)}"
                    logger.error(error_message)
                    result['debug_info']['errors'].append(error_message)
    elif response:
        result['debug_info']['errors'].append(f"DOI resolver returned status code: {response.status_code}")
    return result

def display_nice_table(data, title):
    if not data:
        return
    st.subheader(title)
    formatted_data = {}
    for k, v in data.items():
        display_key = k.replace('_', ' ').title()
        if k == 'organization_names' and isinstance(v, list):
            if len(v) > 3:
                org_str = "; ".join(v[:3]) + f" and {len(v)-3} more..."
            else:
                org_str = "; ".join(v)
            formatted_data["Organizations"] = [org_str]
            if len(v) > 3:
                with st.expander("View All Organizations"):
                    for org in v:
                        st.write(f"• {org}")
        else:
            formatted_data[display_key] = [v]
    
    if formatted_data:
        st.table(pd.DataFrame(formatted_data).T.rename(columns={0: "Value"}))

st.sidebar.header("Options")
show_verbose = st.sidebar.checkbox("Show Additional Details", value=False)
debug_mode = st.sidebar.checkbox("Debug Mode", value=False)

st.sidebar.header("Example DOIs")
examples = {
    "Crossref - Nature Article": "10.1038/nature12373",
    "DataCite - Zenodo Dataset": "10.5281/zenodo.3678326",
    "DataCite - Figshare": "10.6084/m9.figshare.3425729",
    "Crossref - PLOS ONE": "10.1371/journal.pone.0209965"
}

selected_example = st.sidebar.selectbox("Try an example:", [""] + list(examples.keys()))
if selected_example:
    example_doi = examples[selected_example]
else:
    example_doi = ""

with st.container():
    label_col, input_col, button_col = st.columns([1, 4, 1.2])
    with label_col:
        st.markdown("<div style='padding-top: 10px;'><strong>Enter a DOI:</strong></div>", unsafe_allow_html=True)
    with input_col:
        doi_input = st.text_input("", value=example_doi, placeholder="e.g., 10.1038/nature12373", label_visibility="collapsed")
    with button_col:
        submit_button = st.button("Analyze DOI", type="primary", use_container_width=True)

if 'history' not in st.session_state:
    st.session_state.history = []

if submit_button and doi_input:
    with st.spinner('Analyzing DOI...'):
        cleaned_doi = clean_doi(doi_input)
        if not cleaned_doi:
            st.error("No DOI provided or invalid DOI format")
        elif not validate_doi(cleaned_doi):
            st.warning(f"'{cleaned_doi}' does not appear to be a valid DOI format")
            proceed = st.button("Proceed Anyway")
            if not proceed:
                st.stop()
        result = get_doi_info(cleaned_doi)
        if cleaned_doi not in [item['doi'] for item in st.session_state.history]:
            st.session_state.history.append({
                'doi': cleaned_doi,
                'agency': result.get('registration_agency', 'Unknown'),
                'registrant': result.get('registrant', 'Unknown')
            })

    if 'error' in result and result['error']:
        st.error(f"Error: {result.get('message', 'Unknown error')}")
    else:
        st.subheader("Basic Information")
        basic_info = {
            "DOI": result['doi'],
            "Registration Agency": result['registration_agency'] or "Unknown",
            "Registrant/Publisher": result['registrant'] or "Unknown"
        }
        st.table(pd.DataFrame([basic_info]).T.rename(columns={0: "Value"}))
        
        st.subheader("URL Information")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Target URL:**")
            if result['target_url']:
                st.markdown(f"[{result['target_url']}]({result['target_url']})")
            else:
                st.write("Not available")
        with col2:
            if result['final_url'] and result['final_url'] != result['target_url']:
                st.write("**Final URL (after redirects):**")
                st.markdown(f"[{result['final_url']}]({result['final_url']})")
        
        if result['registrant_location']:
            display_nice_table(result['registrant_location'], "Registrant Location")
        
        if result['host_info']:
            host_display = {k: v for k, v in result['host_info'].items() if k != 'aliases'}
            display_nice_table(host_display, "Host Information")
            
            if 'aliases' in result['host_info'] and result['host_info']['aliases']:
                st.write("**Aliases:**")
                for alias in result['host_info']['aliases']:
                    st.write(f"- {alias}")
        
        if result['server_geolocation']:
            geo_display = {k: v for k, v in result['server_geolocation'].items() if k != 'readme'}
            display_nice_table(geo_display, "Target URL Server Geolocation")
            
            if 'loc' in result['server_geolocation']:
                try:
                    lat, lon = result['server_geolocation']['loc'].split(',')
                    map_data = pd.DataFrame({
                        'lat': [float(lat)],
                        'lon': [float(lon)]
                    })
                    st.map(map_data)
                except:
                    st.write("Could not display map from location data")
        
        if result['member_info'] and 'error' not in result['member_info']:
            st.subheader("Member/Provider Information")
            
            if result['registration_agency'] == 'Crossref':
                member = result['member_info']
                if isinstance(member, dict):
                    member_data = {}
                    
                    if 'primary-name' in member:
                        member_data["Name"] = [member.get('primary-name')]
                    if 'location' in member:
                        member_data["Location"] = [member.get('location')]
                    if 'country' in member:
                        member_data["Country"] = [member.get('country')]
                    if 'prefixes' in member:
                        member_data["Prefixes"] = [', '.join(member.get('prefixes', []))]
                    if 'names' in member and member['names']:
                        member_data["Alternative Names"] = [', '.join(member['names'])]
                        
                    if member_data:
                        st.table(pd.DataFrame(member_data).T.rename(columns={0: "Value"}))
                    
                    if show_verbose:
                        with st.expander("Show full member details"):
                            for key, value in sorted(member.items()):
                                if key not in ['counts', 'breakdowns', 'coverage', 'counts-type', 'coverage-type', 'tokens']:
                                    st.write(f"**{key}:** {value}")
            
            elif result['registration_agency'] == 'DataCite':
                if 'data' in result['member_info'] and 'attributes' in result['member_info']['data']:
                    provider = result['member_info']['data']['attributes']
                    provider_data = {}
                    
                    if 'name' in provider:
                        provider_data["Name"] = [provider.get('name')]
                    if 'displayName' in provider and provider.get('displayName') != provider.get('name'):
                        provider_data["Display Name"] = [provider.get('displayName')]
                    if 'country' in provider:
                        provider_data["Country"] = [provider.get('country')]
                    if 'region' in provider:
                        provider_data["Region"] = [provider.get('region')]
                    if 'rorId' in provider:
                        provider_data["ROR ID"] = [provider.get('rorId')]
                    if 'website' in provider:
                        provider_data["Website"] = [provider.get('website')]
                    if 'memberType' in provider:
                        provider_data["Member Type"] = [provider.get('memberType')]
                    if 'organizationType' in provider:
                        provider_data["Organization Type"] = [provider.get('organizationType')]
                        
                    if provider_data:
                        st.table(pd.DataFrame(provider_data).T.rename(columns={0: "Value"}))
                    
                    if show_verbose:
                        with st.expander("Show full provider details"):
                            for key, value in sorted(provider.items()):
                                st.write(f"**{key}:** {value}")
        
        if debug_mode:
            st.subheader("Debug Information")
            st.write(f"**DOI Prefix:** {result['debug_info']['doi_prefix']}")
            
            col1, col2 = st.columns(2)
            with col1:
                if result['debug_info']['member_id']:
                    st.write(f"**Member ID:** {result['debug_info']['member_id']}")
                if result['debug_info']['provider_id']:
                    st.write(f"**Provider ID:** {result['debug_info']['provider_id']}")
            
            with col2:
                if result['debug_info']['member_lookup_method']:
                    st.write(f"**Lookup Method:** {result['debug_info']['member_lookup_method']}")
                if result['debug_info']['lookup_attempts']:
                    st.write(f"**Lookup Attempts:** {', '.join(result['debug_info']['lookup_attempts'])}")
            
            if result['debug_info']['errors']:
                with st.expander("Errors encountered"):
                    for i, error in enumerate(result['debug_info']['errors'], 1):
                        st.write(f"{i}. {error}")
            
            with st.expander("Raw Result Data"):
                st.json(result)

if st.session_state.history:
    st.sidebar.header("Search History")
    history_df = pd.DataFrame(st.session_state.history)
    st.sidebar.dataframe(history_df, hide_index=True)
    
    if st.sidebar.button("Clear History"):
        st.session_state.history = []
        st.rerun()

st.markdown("---")
st.markdown("**DOI Analyzer** - A tool for gathering details about Digital Object Identifiers from Crossref and DataCite")
st.markdown(
    "This application uses the Crossref and DataCite APIs to gather information about DOIs. "
    "It provides insights about the registration agency, publisher, and target URL hosting details."
)