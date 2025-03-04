import re
from typing import Dict, List, Any, Union

class P4RuleGenerator:
    def __init__(self):
        """Initialize the P4 rule generator."""
        pass
    
    def _convert_decision_path_to_rule_statement(self, decision_path: str) -> str:
        """
        Convert the decision path from the model to a rule statement format
        that matches the expected input for the convert_statement_to_script function.
        
        Args:
            decision_path: Text representation of the decision path from the model
            
        Returns:
            Rule statement in the expected format
        """
        # Parse the decision path string
        lines = decision_path.split("\n")
        if len(lines) < 2:
            raise ValueError("Invalid decision path format")
            
        # Extract node information
        nodes = []
        for part in lines[1].split(" → "):
            part = part.strip()
            if "Leaf Node" in part:
                # This is a classification result
                node_id = int(part.split("Leaf Node ")[1].split(":")[0])
                classification = "video" if "video" in part else "non-video"
                nodes.append({
                    "type": "leaf",
                    "id": node_id,
                    "class": "1" if classification == "video" else "0"  # 1 for video, 0 for non-video
                })
            else:
                # This is a decision node
                node_parts = part.split(": ")
                if len(node_parts) < 2:
                    continue
                
                node_id = int(node_parts[0].split("Node ")[1])
                feature_parts = node_parts[1].split(" ")
                if len(feature_parts) < 3:
                    continue
                
                feature = feature_parts[0]
                operator = feature_parts[1]
                threshold = float(feature_parts[2])
                
                nodes.append({
                    "type": "decision",
                    "id": node_id,
                    "feature": feature,
                    "operator": operator,
                    "threshold": threshold
                })
        
        # Find the leaf node (it should be the last one)
        leaf_node = None
        for node in reversed(nodes):
            if node["type"] == "leaf":
                leaf_node = node
                break
        
        if not leaf_node:
            raise ValueError("No classification found in decision path")
        
        # Build conditions
        conditions = []
        for node in nodes:
            if node["type"] == "decision":
                condition = f"({node['feature']} {node['operator']} {node['threshold']})"
                conditions.append(condition)
        
        # Create the rule statement in the expected format
        # Format: "index if condition1 and condition2 then class:X|proba:Y%"
        conditions_str = " and ".join(conditions)
        rule_statement = f"{leaf_node['id']} if {conditions_str} then class:{leaf_node['class']}|proba:100%"
        
        return rule_statement
    
    def convert_statement_to_script(self, statement: str) -> str:
        """
        Convert a rule statement to P4 table entries.
        Modified version that handles duplicate fields by using a dictionary.
        
        Args:
            statement: Rule statement in the format "index if conditions then class:X|proba:Y%"
            
        Returns:
            String containing P4 table entry script
        """
        index = statement.split(' if ')[0]
        conditions = statement.split('if ')[1].split(' then ')[0].split(' and ')

        action = statement.split('then ')[1].split(':')[1].split('|')[0].strip()

        pattern = r"proba:\s+(\d+\.\d+)%"
        match = re.search(pattern, statement)
        script = "TABLE ENTRIES: \n"
        script = f"te = table_entry['IngressPipeImpl.l2_exact_table'](action="
        if action[0] == "1":
            script += "'IngressPipeImpl.drop')"
        elif action[0] == '0':
            script += "'IngressPipeImpl.set_egress_port')"

        script += "\n"
        
        # Use a dictionary to track match fields and avoid duplicates
        match_fields = {}
        
        for condition in conditions:
            condition_parts = condition.split()
            field = condition_parts[0].strip('(')
            op = condition_parts[1]
            value = condition_parts[2].strip(')')
            
            # Determine field name in P4 and the range value
            p4_field = None
            range_value = None
            
            if field == "Destination.Port":
                p4_field = "hdr.tcp.dst_port"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..65535"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "Source.Port":
                p4_field = "hdr.tcp.src_port"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..65535"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "S_octet4":
                p4_field = "hdr.custom.dst_octet4"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "S_octet3":
                p4_field = "hdr.custom.dst_octet3"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "S_octet2":
                p4_field = "hdr.custom.dst_octet2"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "S_octet1":
                p4_field = "hdr.custom.dst_octet1"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "D_octet4":
                p4_field = "hdr.custom.dst_octet4"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "D_octet3":
                p4_field = "hdr.custom.dst_octet3"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "D_octet2":
                p4_field = "hdr.custom.dst_octet2"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
            elif field == "D_octet1":
                p4_field = "hdr.custom.dst_octet1"
                if op == '>':
                    range_value = f"{int(float(value) + 1)}..255"
                else:
                    range_value = f"0..{int(float(value))}"
                    
            # Store in dictionary (last value for each field will be used)
            if p4_field:
                match_fields[p4_field] = range_value
        
        # Add all match fields from the dictionary
        for field, value in match_fields.items():
            script += f"te.match['{field}'] = '{value}'\n"
            
        if action[0] == "0":
            script += f"te.action['port_num'] = '3'\n"
        script += f"te.priority = {index}\n"
        script += f"te.insert()\n"
        return script
    
    def generate_p4_rules(self, decision_path: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate P4 rules from the decision path.
        
        Args:
            decision_path: Text representation of the decision path
            features: Original packet features
            
        Returns:
            Dictionary with P4 script and rules information
        """
        # Convert the decision path to a rule statement
        rule_statement = self._convert_decision_path_to_rule_statement(decision_path)
        
        # Convert the rule statement to a P4 script
        script = self.convert_statement_to_script(rule_statement)
        
        # Return both the script and parsed information about the rule
        return {
            "script": script,
            "rule_statement": rule_statement,
            "table": "IngressPipeImpl.l2_exact_table",
            "is_drop": "drop" in script
        }
    
    def save_rule_to_file(self, script: str, output_file: str = "Entries_final.txt"):
        """
        Save a P4 rule script to a file.
        
        Args:
            script: P4 rule script
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            f.write(script + '\n')
        return output_file