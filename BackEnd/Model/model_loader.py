import joblib
import os
import numpy as np
from sklearn.tree import _tree

class PacketClassifier:
    def __init__(self, model_path='Model\model.pkl'):
        """Load the decision tree model from the pkl file."""
        self.model = joblib.load(model_path)
        
        # Feature names the model was trained on
        self.feature_names = [
            'Source.Port', 'Destination.Port', 
            'D_octet1', 'D_octet2', 'D_octet3', 'D_octet4',
            'S_octet1', 'S_octet2', 'S_octet3', 'S_octet4'
        ]
    
    def classify(self, features_dict):
        """Classify a packet as video or non-video."""
        # Convert dictionary to ordered list matching the model's expected features
        features_list = [
            features_dict['Source.Port'],
            features_dict['Destination.Port'],
            features_dict['D_octet1'],
            features_dict['D_octet2'],
            features_dict['D_octet3'],
            features_dict['D_octet4'],
            features_dict['S_octet1'],
            features_dict['S_octet2'],
            features_dict['S_octet3'],
            features_dict['S_octet4']
        ]
        
        # Convert to numpy array and reshape for single sample prediction
        features_array = np.array(features_list).reshape(1, -1)
        
        # Make prediction
        prediction = self.model.predict(features_array)[0]
        probability = self.model.predict_proba(features_array)[0].max()
        
        return {
            'is_video': bool(prediction == 1),  # Assuming 1 is for video traffic
            'confidence': float(probability),
            'classification': 'video' if prediction == 1 else 'non-video'
        }
    
    def get_tree_rules(self, features_dict):
        """Extract the decision path from tree and generate a text representation."""
        # Convert dictionary to ordered list matching the model's expected features
        features_list = [
            features_dict['Source.Port'],
            features_dict['Destination.Port'],
            features_dict['D_octet1'],
            features_dict['D_octet2'],
            features_dict['D_octet3'],
            features_dict['D_octet4'],
            features_dict['S_octet1'],
            features_dict['S_octet2'],
            features_dict['S_octet3'],
            features_dict['S_octet4']
        ]
        
        feature_names = self.feature_names
        tree = self.model.tree_
        
        # Get the decision path for this sample
        features_array = np.array(features_list).reshape(1, -1)
        decision_path = self.model.decision_path(features_array)
        
        # Extract the nodes in the decision path
        node_indices = decision_path.indices
        
        # Generate text representation of the decision path
        rules_text = "Decision Path:\n"
        
        for i, node_id in enumerate(node_indices):
            if i > 0:
                rules_text += " → "
            
            # Check if it's a leaf node
            if tree.children_left[node_id] == _tree.TREE_LEAF:
                value = tree.value[node_id]
                class_label = 'video' if np.argmax(value) == 1 else 'non-video'
                rules_text += f"Leaf Node {node_id}: Classified as {class_label}"
            else:
                # Get the split feature and threshold
                feature = feature_names[tree.feature[node_id]]
                threshold = tree.threshold[node_id]
                
                # Check which child was taken
                next_node = node_indices[i+1] if i+1 < len(node_indices) else None
                if next_node is not None:
                    if next_node == tree.children_left[node_id]:
                        operator = "<="
                    else:
                        operator = ">"
                    
                    rules_text += f"Node {node_id}: {feature} {operator} {threshold:.2f}"
        
        return rules_text