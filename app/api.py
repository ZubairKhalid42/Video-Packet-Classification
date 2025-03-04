# API endpoint definitions
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
from Model.model_loader import PacketClassifier
from App.rules_conversion import P4RuleGenerator

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

@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}