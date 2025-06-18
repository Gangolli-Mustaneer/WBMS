import hashlib
import json
import os
import re

import magic
import requests
import yara
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z', 'txt', 'js', 'py', 'php'}

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Load YARA rules
def load_yara_rules():
    try:
        rules_path = os.path.join(os.path.dirname(__file__), 'rules', 'malware_rules.yar')
        if not os.path.exists(rules_path):
            print(f"YARA rules file not found at: {rules_path}")
            return None
        rules = yara.compile(rules_path)
        return rules
    except Exception as e:
        print(f"Error loading YARA rules: {str(e)}")
        return None

# Google Safe Browsing API configuration
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
GOOGLE_SAFE_BROWSING_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan/file', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename):
            return jsonify({'error': f'File type not allowed. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            
            if not os.path.exists(filepath):
                print(f"File not found at: {filepath}")
                return jsonify({'error': 'File not found after saving'}), 500

            print(f"File saved successfully at: {filepath}")
            print(f"File size: {os.path.getsize(filepath)} bytes")

            # Get file information
            with open(filepath, 'rb') as f:
                file_content = f.read()
                file_size = len(file_content)
                file_type = magic.from_buffer(file_content, mime=True)
                file_hash = hashlib.sha256(file_content).hexdigest()

            # Initialize detection results
            matches = []
            rules = load_yara_rules()
            
            if rules is None:
                return jsonify({'error': 'Failed to load scanning rules'}), 500

            # Determine file category for specific scanning approaches
            is_office_file = filename.lower().endswith(('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'))
            is_pdf_file = filename.lower().endswith('.pdf')
            is_executable = filename.lower().endswith(('.exe', '.dll'))
            is_archive = filename.lower().endswith(('.zip', '.rar', '.7z'))

            try:
                # Specific scanning logic based on file type
                if is_office_file:
                    # For Office files, only apply Office-specific rules and check for macros
                    all_matches = rules.match(filepath)
                    matches = [match for match in all_matches if 
                             match.rule.startswith('Office_') or 
                             'macro' in match.rule.lower() or 
                             'malicious_document' in match.rule.lower()]
                    
                    # Additional validation for Office files
                    if filename.lower().endswith(('.xlsx', '.xls')):
                        # Check if file actually has the Excel file signature
                        excel_signatures = [b'PK\x03\x04', b'\xD0\xCF\x11\xE0']  # ZIP (XLSX) and OLE (XLS) signatures
                        has_valid_signature = any(file_content.startswith(sig) for sig in excel_signatures)
                        if not has_valid_signature:
                            matches.append({'rule': 'Invalid_Excel_File', 
                                         'meta': {'malware_type': 'Suspicious',
                                                 'description': 'File does not match Excel format signature'}})
                
                elif is_pdf_file:
                    # For PDFs, apply PDF-specific rules
                    all_matches = rules.match(filepath)
                    matches = [match for match in all_matches if 
                             'pdf' in match.rule.lower() or 
                             'malicious_document' in match.rule.lower()]
                    
                elif is_executable:
                    # For executables, apply all rules but with higher scrutiny
                    matches = rules.match(filepath)
                    
                elif is_archive:
                    # For archives, check for suspicious patterns
                    matches = rules.match(filepath)
                else:
                    # For other files, apply general rules
                    matches = rules.match(filepath)

                print(f"YARA matches: {matches}")
                
                # Validate matches to reduce false positives
                validated_matches = []
                for match in matches:
                    # Skip matches with low confidence or generic detections
                    if hasattr(match, 'meta'):
                        confidence = match.meta.get('confidence', 0)
                        if confidence and confidence < 50:  # Skip low confidence matches
                            continue
                    validated_matches.append(match)
                
                matches = validated_matches

            except Exception as e:
                print(f"Error during YARA scan: {str(e)}")
                return jsonify({'error': f'Error during file scanning: {str(e)}'}), 500

            # Format detection details
            detection_details = []
            for match in matches:
                if isinstance(match, dict):  # Handle custom detection entries
                    match_data = {
                        'rule': match.get('rule', 'Unknown'),
                        'malware_type': match.get('meta', {}).get('malware_type', 'Unknown'),
                        'description': match.get('meta', {}).get('description', 'No description'),
                        'severity': match.get('meta', {}).get('severity', 'Unknown'),
                    }
                else:  # Handle YARA match objects
                    match_data = {
                        'rule': match.rule,
                        'malware_type': match.meta.get('malware_type', 'Unknown'),
                        'description': match.meta.get('description', 'No description'),
                        'severity': match.meta.get('severity', 'Unknown'),
                        'strings': []
                    }
                    
                    if hasattr(match, 'strings') and match.strings:
                        for string_match in match.strings:
                            try:
                                matched_data = getattr(string_match, 'data', None) or getattr(string_match, 'matched', None)
                                offset = getattr(string_match, 'offset', None)
                                identifier = getattr(string_match, 'identifier', None)
                                if matched_data is not None and offset is not None:
                                    if isinstance(matched_data, bytes):
                                        matched_data = matched_data.decode(errors='replace')
                                    match_data['strings'].append({
                                        'identifier': identifier,
                                        'matched': matched_data,
                                        'offset': offset
                                    })
                            except Exception as e:
                                print(f"Error processing string match: {str(e)}")
                                continue
                
                detection_details.append(match_data)

            # Collect all unique malware types detected
            malware_types = list({d['malware_type'] for d in detection_details if d['malware_type'] and d['malware_type'] != 'Unknown'})

            result = {
                'file_name': filename,
                'file_size': f"{file_size / 1024:.2f} KB",
                'file_type': file_type,
                'sha256_hash': file_hash,
                'malware_detected': len(validated_matches) > 0,  # Only use validated matches
                'detection_details': detection_details,
                'malware_types': malware_types
            }

            return jsonify(result)

        except Exception as e:
            print(f"Error processing file: {str(e)}")
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500

        finally:
            # Clean up the temporary file
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                print(f"Error cleaning up file: {str(e)}")

    except Exception as e:
        print(f"Error scanning file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan_url', methods=['POST'])
def scan_url():
    try:
        url = request.form.get('url', '').strip()
        
        # Validate URL format
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        # More permissive URL validation pattern
        if not re.match(r'^https?://[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+[/\w\-\.~:/?#[\]@!$&\'()*+,;=]*$', url):
            return jsonify({'error': 'Invalid URL format. Please enter a valid URL starting with http:// or https://'}), 400

        # Check if API key is configured
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return jsonify({
                'error': 'Google Safe Browsing API key is not configured',
                'details': 'Please set the GOOGLE_SAFE_BROWSING_API_KEY environment variable in your .env file'
            }), 500

        # Prepare the request to Google Safe Browsing API
        payload = {
            'client': {
                'clientId': 'malware-scanner',
                'clientVersion': '1.0.0'
            },
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }

        # Make the API request with timeout
        response = requests.post(
            f'{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}',
            json=payload,
            timeout=10
        )

        # Check if the request was successful
        if response.status_code == 200:
            result = response.json()
            if result:  # If there are matches
                return jsonify({
                    'url': url,
                    'is_malicious': True,
                    'threat_type': result.get('matches', [{}])[0].get('threatType', 'Unknown'),
                    'platform': result.get('matches', [{}])[0].get('platformType', 'Unknown'),
                    'details': result
                })
            else:  # No matches found
                return jsonify({
                    'url': url,
                    'is_malicious': False,
                    'message': 'No threats detected'
                })
        else:
            error_msg = f'Error checking URL: {response.status_code}'
            try:
                error_details = response.json()
                error_msg += f' - {error_details.get("error", {}).get("message", "Unknown error")}'
            except:
                pass
            return jsonify({'error': error_msg}), response.status_code

    except requests.exceptions.Timeout:
        return jsonify({'error': 'Request timed out while checking URL'}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Error checking URL: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@app.route('/scan/hash', methods=['POST'])
def scan_hash():
    try:
        data = request.get_json()
        if not data or 'hash' not in data:
            return jsonify({'error': 'No hash provided'}), 400

        hash_value = data['hash'].lower()
        if not re.match(r'^[a-f0-9]{64}$', hash_value):
            return jsonify({'error': 'Invalid SHA-256 hash format'}), 400

        # sample malware hashes
        sample_malware_hashes = {
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': 'Empty file',
            'db349b97c37d22f5ea1d1841e3c89eb4c1b3df6c8f0f7c9d3b6d8aefb6a3b60b': 'WannaCry Ransomware',
            '71b6a493388e7d0b40c83ce903bc6b2e3e0967b6c5d1c2b6b8e5b8e8e8e8e8e8': 'NotPetya Ransomware',
            'e2fc714c4727ee9395f324cd2e7f331f1b7e2e7f331f1b7e2e7f331f1b7e2e7f': 'Locky Ransomware',
            'cc175b9c0f1b6a831c399e269772661c1b6a831c399e269772661c1b6a831c3': 'Zeus Trojan',
            '8e296a067a37563370ded05f5a3bf3ec70ded05f5a3bf3ec70ded05f5a3bf3ec': 'Dridex Trojan',
            '4e07408562bedb8b60ce05c1decfe3ad16b7223095bfc0c6d2c1b7e2e7f331f1': 'Emotet Trojan',
            'ef2d127de37b942a45e4b14fc5d8de0166b1b7e2e7f331f1b7e2e7f331f1b7e2': 'TrickBot Trojan',
            '8f434346b3e2e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa': 'Adware.Generic',
            'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2': 'Adware.Downloader',
            'b2cfa418b6e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa0b1': 'Worm.Generic',
            'c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2': 'Worm.AutoRun',
            'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4': 'Rootkit.Generic',
            'd1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2': 'Rootkit.Hidden',
            'd4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3': 'Backdoor.Generic',
            'e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2': 'Backdoor.Bot',
            'f1e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100': 'Virus.Generic',
            'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899': 'Virus.Macro',
            '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa': 'Spyware.Generic',
            '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff': 'Spyware.Keylogger',
            '2233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011': 'Ransomware.Generic',
            '33445566778899aabbccddeeff00112233445566778899aabbccddeeff001122': 'Ransomware.Cryptolocker',
            '445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233': 'Trojan.Dropper',
            '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344': 'Trojan.Banker',
            '66778899aabbccddeeff00112233445566778899aabbccddeeff001122334455': 'Exploit.Generic',
            '778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566': 'Exploit.PDF',
            '8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677': 'Exploit.Office',
            '99aabbccddeeff00112233445566778899aabbccddeeff001122334455667788': 'Exploit.Java',
            '6bfbc71cc0708e75f6fb1b49659f8d6400213e566c2ab11c8155c7c4585018f0': 'Exploit.C',
            'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899': 'Exploit.PHP',
            '6290f755b922876ccc59a56d0c3ffda8384c10d02818d591f884ef9b7a1fe60f': 'Suspicious_Test_File'
        }

        result = {
            'hash': hash_value,
            'malware_detected': hash_value in sample_malware_hashes,
            'detection_details': {
                'type': sample_malware_hashes.get(hash_value, None)
            } if hash_value in sample_malware_hashes else None
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)