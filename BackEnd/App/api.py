# API endpoint definitions
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
from Model.model_loader import PacketClassifier
from App.rules_conversion import P4RuleGenerator
from fastapi import File, UploadFile
import tempfile
import os
from scapy.all import rdpcap
import pandas as pd
from typing import List

router = APIRouter()
classifier = PacketClassifier()
rule_generator = P4RuleGenerator()

# Directory for saving rule files
RULES_DIR = os.environ.get("RULES_DIR", "/tmp/rules")
os.makedirs(RULES_DIR, exist_ok=True)

class PacketFeatures(BaseModel):
    """Input packet features for classification."""
    Source_Port: int
    Destination_Port: int
    D_octet1: int
    D_octet2: int
    D_octet3: int
    D_octet4: int
    S_octet1: int
    S_octet2: int
    S_octet3: int
    S_octet4: int

    # Alias field names to match model's expected format
    class Config:
     @staticmethod
     def json_schema_extra(schema, model):
        schema["properties"]["Source_Port"]["title"] = "Source.Port"
        schema["properties"]["Destination_Port"]["title"] = "Destination.Port"

class ClassificationResponse(BaseModel):
    """Response with classification results and P4 rules."""
    classification: str
    confidence: float
    decision_path: str
    p4_rule: Dict[str, Any]
    rule_file: Optional[str] = None

class PcapAnalysisResponse(BaseModel):
    """Response with PCAP analysis summary."""
    total_packets: int
    classified_packets: int
    video_packets: int
    non_video_packets: int
    classifications: List[ClassificationResponse]

def save_rule_to_file(rule_script: str, packet_id: str):
    """Background task to save rule to a file."""
    filename = f"{RULES_DIR}/rule_{packet_id}.txt"
    with open(filename, 'w') as f:
        f.write(rule_script)
    return filename

@router.post("/classify", response_model=ClassificationResponse)
async def classify_packet(features: PacketFeatures, background_tasks: BackgroundTasks):
    """Classify a packet and generate P4 rules."""
    try:
        # Convert to dictionary with proper field names for the model
        features_dict = {
            'Source.Port': features.Source_Port,
            'Destination.Port': features.Destination_Port,
            'D_octet1': features.D_octet1,
            'D_octet2': features.D_octet2,
            'D_octet3': features.D_octet3,
            'D_octet4': features.D_octet4,
            'S_octet1': features.S_octet1,
            'S_octet2': features.S_octet2,
            'S_octet3': features.S_octet3,
            'S_octet4': features.S_octet4
        }
        
        # Get classification
        result = classifier.classify(features_dict)
        
        # Get decision path
        decision_path = classifier.get_tree_rules(features_dict)
        
        # Generate P4 rule
        p4_rule = rule_generator.generate_p4_rules(decision_path, features_dict)
        
        # Generate a unique ID for this packet based on features
        packet_id = f"{features.S_octet1}_{features.S_octet2}_{features.S_octet3}_{features.S_octet4}_{features.Source_Port}_{features.Destination_Port}"
        
        # Save rule script to file in background
        background_tasks.add_task(save_rule_to_file, p4_rule["script"], packet_id)
        
        return {
            "classification": result["classification"],
            "confidence": result["confidence"],
            "decision_path": decision_path,
            "p4_rule": p4_rule,
            "rule_file": f"/tmp/rules/rule_{packet_id}.txt"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Classification error: {str(e)}")


def extract_features(pcap_file):
    """
    Extract features from a PCAP file for classification.
    Returns a list of feature dictionaries, one per packet.
    """
    packets = rdpcap(pcap_file)
    features = []
    
    for packet in packets:
        # Skip packets without IP or TCP layers
        if 'IP' not in packet or 'TCP' not in packet:
            continue
            
        source_port = packet['TCP'].sport
        destination_port = packet['TCP'].dport
        
        # Extract IP address octets
        source_ip_octets = [int(octet) for octet in packet['IP'].src.split('.')]
        destination_ip_octets = [int(octet) for octet in packet['IP'].dst.split('.')]
        
        # Ensure we have 4 octets
        while len(source_ip_octets) < 4:
            source_ip_octets.append(0)
        while len(destination_ip_octets) < 4:
            destination_ip_octets.append(0)
        
        # Construct feature vector
        feature_vector = {
            'Source.Port': source_port,
            'Destination.Port': destination_port,
            'D_octet1': destination_ip_octets[0],
            'D_octet2': destination_ip_octets[1],
            'D_octet3': destination_ip_octets[2],
            'D_octet4': destination_ip_octets[3],
            'S_octet1': source_ip_octets[0],
            'S_octet2': source_ip_octets[1],
            'S_octet3': source_ip_octets[2],
            'S_octet4': source_ip_octets[3],
        }
        features.append(feature_vector)
    
    return features

@router.post("/analyze-pcap", response_model=PcapAnalysisResponse)
async def analyze_pcap(file: UploadFile = File(...), background_tasks: BackgroundTasks = None):
    """
    Analyze a PCAP file and classify all packets using the ML model.
    Returns classification results for each packet and generated P4 rules.
    """
    try:
        # Create a temporary file to save the uploaded PCAP
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as temp_file:
            # Write uploaded file content to the temp file
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        # Extract features from the PCAP file
        features_list = extract_features(temp_file_path)
        
        # Get all packets for total count
        packets = rdpcap(temp_file_path)
        
        # Process each packet
        results = []
        for i, features_dict in enumerate(features_list):
            # Get classification
            result = classifier.classify(features_dict)
            
            # Get decision path
            decision_path = classifier.get_tree_rules(features_dict)
            
            # Generate P4 rule
            p4_rule = rule_generator.generate_p4_rules(decision_path, features_dict)
            
            # Generate a unique ID for this packet
            packet_id = f"pcap_{i}_{features_dict['S_octet1']}_{features_dict['S_octet2']}_{features_dict['S_octet3']}_{features_dict['S_octet4']}_{features_dict['Source.Port']}_{features_dict['Destination.Port']}"
            
            # Save rule script to file in background if requested
            rule_file = None
            if background_tasks:
                background_tasks.add_task(save_rule_to_file, p4_rule["script"], packet_id)
                rule_file = f"/tmp/rules/rule_{packet_id}.txt"
            
            # Add result to the list
            results.append({
                "classification": result["classification"],
                "confidence": result["confidence"],
                "decision_path": decision_path,
                "p4_rule": p4_rule,
                "rule_file": rule_file,
                "packet_index": i
            })
        
        # Clean up the temporary file
        os.unlink(temp_file_path)
        
        # Count statistics
        video_packets = sum(1 for r in results if r["classification"] == "video")
        non_video_packets = len(results) - video_packets
        
        return {
            "total_packets": len(packets),
            "classified_packets": len(results),
            "video_packets": video_packets,
            "non_video_packets": non_video_packets,
            "classifications": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PCAP analysis error: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}