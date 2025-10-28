import os
import json
import io
from flask import Flask, request, jsonify, render_template
from flask_compress import Compress 
from google import genai
from google.genai import types
from google.genai.errors import APIError

# =========================================================================
# Read API Key from environment variables
API_KEY = os.environ.get('GEMINI_API_KEY')

if not API_KEY:
    print("FATAL ERROR: GEMINI_API_KEY is not set in environment.")
    raise EnvironmentError("GEMINI_API_KEY is required but not found in environment variables.")

try:
    client = genai.Client(api_key=API_KEY)
except Exception as e:
    print(f"Error initializing Gemini client: {e}")
    raise

# =========================================================================

app = Flask(__name__, template_folder='templates')
Compress(app) 

# Required JSON schema for structured response (English properties and descriptions)
ANALYSIS_SCHEMA = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "risk_assessment": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "score": types.Schema(type=types.Type.INTEGER, description="Total risk score based on findings (0-100)."),
                "level": types.Schema(type=types.Type.STRING, description="Descriptive risk level (Critical, High, Medium, Low)."),
                "color_class": types.Schema(type=types.Type.STRING, description="Color class for styling (e.g., critical, high, low).")
            },
            required=["score", "level", "color_class"]
        ),
        "attack_narrative": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "summary": types.Schema(type=types.Type.STRING, description="A detailed narrative summary of the detected attack."),
                "attack_origin_country": types.Schema(type=types.Type.STRING, description="Probable origin country of the attacker."),
                "attacker_intent": types.Schema(type=types.Type.STRING, description="The likely intent of the attacker (e.g., Data Exfiltration, Denial of Service)."),
                "stages_found": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(type=types.Type.STRING),
                    description="List of MITRE ATT&CK or Kill Chain stages detected."
                )
            },
            required=["summary", "attack_origin_country", "attacker_intent", "stages_found"]
        ),
        "detailed_findings": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "critical": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Finding": types.Schema(type=types.Type.STRING, description="Detailed description of the finding."),
                            "Recommendation": types.Schema(type=types.Type.STRING, description="Immediate remediation recommendation.")
                        }
                    )
                ),
                "high": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Finding": types.Schema(type=types.Type.STRING, description="Detailed description of the finding."),
                            "Recommendation": types.Schema(type=types.Type.STRING, description="Immediate remediation recommendation.")
                        }
                    )
                ),
                "medium": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Finding": types.Schema(type=types.Type.STRING, description="Detailed description of the finding."),
                            "Recommendation": types.Schema(type=types.Type.STRING, description="Immediate remediation recommendation.")
                        }
                    )
                ),
                "low": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Finding": types.Schema(type=types.Type.STRING, description="Detailed description of the finding."),
                            "Recommendation": types.Schema(type=types.Type.STRING, description="Immediate remediation recommendation.")
                        }
                    )
                )
            }
        ),
        "tables": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "ip_intelligence": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "IP Address": types.Schema(type=types.Type.STRING),
                            "Organization": types.Schema(type=types.Type.STRING),
                            "Country": types.Schema(type=types.Type.STRING),
                            "Role": types.Schema(type=types.Type.STRING),
                            "Status": types.Schema(
                                type=types.Type.STRING, 
                                description="Live or Dead for Public IP. MUST use 'N/A' or 'Private' for local/internal network ranges (e.g., 192.168.x.x, 10.x.x.x)."
                            ) 
                        }
                    ),
                    description="List of IP addresses, their context, and live/dead status. Private IPs MUST be classified as N/A or Private."
                ),
                "rca_analysis": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Analysis Element": types.Schema(type=types.Type.STRING),
                            "Result/Details": types.Schema(type=types.Type.STRING),
                            "Recommendation": types.Schema(type=types.Type.STRING)
                        }
                    ),
                    description="Root Cause Analysis table."
                ),
                "yara_analysis": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "Matching Rule": types.Schema(type=types.Type.STRING),
                            "Severity": types.Schema(type=types.Type.STRING),
                            "Result": types.Schema(type=types.Type.STRING)
                        }
                    )
                ),
            }
        ),
        "interactive_timeline": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "items": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "id": types.Schema(type=types.Type.INTEGER),
                            "content": types.Schema(type=types.Type.STRING, description="Short event description."),
                            "start": types.Schema(type=types.Type.STRING, description="ISO 8601 timestamp."),
                            "group": types.Schema(type=types.Type.STRING, description="Group ID for timeline categorization.")
                        }
                    )
                ),
                "groups": types.Schema(
                    type=types.Type.ARRAY,
                    items=types.Schema(
                        type=types.Type.OBJECT,
                        properties={
                            "id": types.Schema(type=types.Type.STRING),
                            "content": types.Schema(type=types.Type.STRING, description="Group label (e.g., Reconnaissance, Exploitation).")
                        }
                    )
                )
            }
        ),
        "recommendations": types.Schema(
            type=types.Type.ARRAY,
            items=types.Schema(type=types.Type.STRING),
            description="List of summary recommendations."
        ),
        "analysis_metadata": types.Schema(
            type=types.Type.OBJECT,
            properties={
                "analysis_time": types.Schema(type=types.Type.STRING, description="Timestamp of when the analysis completed.")
            }
        )
    },
    required=[
        "risk_assessment",
        "attack_narrative",
        "detailed_findings",
        "tables",
        "recommendations",
        "analysis_metadata"
    ]
)

# The core prompt instructing the model to perform the analysis and use the schema
SYSTEM_INSTRUCTION = (
    "You are an expert Cyber Security Analyst and Digital Forensics expert. "
    "Your task is to analyze the provided raw log/configuration data and produce a structured security report. "
    "ALL OUTPUT MUST BE STRICTLY in the ENGLISH language. "
    "Your response MUST be a single JSON object that conforms precisely to the provided JSON schema. "
    "Do not include any markdown formatting (e.g., ```json) or explanatory text outside of the JSON object. "
    "Ensure all analysis (narrative, findings, tables) is insightful and accurate. "
    "For IP intelligence, strictly follow the rule: Private IP addresses (10.x.x.x, 192.168.x.x, 172.16.x.x to 172.31.x.x) MUST have 'N/A' or 'Private' status."
)

@app.route('/')
def index():
    # Renders the English HTML template
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part in the request."}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file."}), 400

    file_extension = file.filename.rsplit('.', 1)[-1].lower()
    
    # Check for allowed file types
    if file_extension in ['log', 'txt', 'csv', 'json', 'jsonl', 'conf', 'cfg', 'ini']:
        try:
            # Read file content safely
            file_content = file.read().decode('utf-8', errors='ignore')
            
            # Context for the model
            prompt = (
                f"Analyze the following raw data/log file content. The file type is .{file_extension}. "
                f"Generate a comprehensive cyber security analysis report strictly in English, adhering to the provided JSON schema. "
                f"RAW DATA CONTENT:\n---\n{file_content}\n---"
            )

            # Call the Gemini API
            response = client.models.generate_content(
                model='gemini-2.5-pro',
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_INSTRUCTION,
                    response_mime_type="application/json",
                    response_schema=ANALYSIS_SCHEMA,
                    temperature=0.0
                )
            )

            try:
                # 1. Clean the response: remove potential markdown wrappers
                json_text = response.text.strip()
                if json_text.startswith('```json'):
                    json_text = json_text.lstrip('```json').rstrip('```')
                
                # 2. Check to ensure the text starts with { or [ before attempting to convert
                if not json_text.startswith('{') and not json_text.startswith('['):
                    print(f"JSON Parsing Failed: Response did not start with {{ or [. Beginning of text: {json_text[:200]}...")
                    raise json.JSONDecodeError("Response is not valid JSON.", doc=json_text, pos=0)

                analysis_data = json.loads(json_text)
                # Success response (English data)
                return jsonify(analysis_data)
            
            except json.JSONDecodeError as e:
                # JSON parsing error
                return jsonify({"success": False, "error": "Failed to parse AI response into JSON. The model may have added unwanted text. (JSON Decode Error)"}), 500

        except APIError as e:
            # API key, quota, or restriction error
            return jsonify({"success": False, "error": f"Error connecting to Gemini API (API Error): {e.message}"}), 500
        except Exception as e:
            # General error handling
            return jsonify({"success": False, "error": f"An unexpected error occurred during processing: {e}"}), 500

    return jsonify({"success": False, "error": "Unsupported file type. Please use .log, .txt, .csv, .json, .jsonl, .conf, .cfg, or .ini"}), 400

if __name__ == '__main__':
    # Vercel deployment environment usually sets the port, default is 5000
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000))