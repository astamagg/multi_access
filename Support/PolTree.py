from typing import List, Tuple
from Support.util import print2D
import sys

#TODO the binary tree comparison is case sensitive, how can I fix this...or is it okay as this is only for proof-of-concept
#TODO can try to add an OR, if OR then both attributes should be in a Node and should be removed, in the case of an OR include the string in the NODE so we can
    #can estimate on the OR as well
    #can slow the rate of growth

#Node class which stores information about the content of the node, whether it is a leaf and its children
class Node:
    def __init__(self, val: str, leaf_bool: bool) -> ():
        self.left = None
        self.right = None
        self.data = val
        self.leaf = leaf_bool

#Tree object which knows the root of the tree
class Tree:
    def __init__(self):
        self.root = None
    
    #Add node objects to a tree
    def add(self, val: str, leaf: bool, parent = None, direction = -1) -> ():
        if parent is None:
            self.root = Node(val, leaf)
            return self.root
        if direction == 0:
            parent.right = Node(val, leaf)
            return parent.right
        else:
            parent.left = Node(val, leaf)
            return parent.left

#Object that represents an attribute-value pair          
class avp_values:
    def __init__(self, attribute: str, value: str) -> ():
        self.attribute = attribute
        self.value = value

#Policy class, where we add rules to your ruleset and store policies as relations of rules
class Policy:
    frequencies = {}

    def __init__(self):
        self.rules = {}
        self.current_index = 0
        self.avp_list = []
    
    #Gets list of attributes, operations between pair of attributes and the corresponding value.
    #def create_rule(self, attributes: list, operators: list, values: list) -> (int):
    #    rule_set = []
    #    for i in range(len(attributes) - 1):
    #        attribute_values = avp_values(attributes[i], values[i])
    #        self.avp_list.append(attribute_values)
    #        rule_set.append((attribute_values, operators[i], avp_values(attributes[i+1], values[i+1])))

    #    attribute_values = avp_values(attributes[len(attributes)-1], values[len(values)-1])
    #    self.avp_list.append(attribute_values)
    #    self.rules[self.current_index] = rule_set
    #    self.current_index += 1

    #    return self.current_index

    def create_rule(self, attributes: list, values: list) -> (int):
        rule_set = []
        for i in range(len(attributes) - 1):
            attribute_values = avp_values(attributes[i], values[i])
            self.avp_list.append(attribute_values)
            rule_set.append((attribute_values, avp_values(attributes[i+1], values[i+1])))

        attribute_values = avp_values(attributes[len(attributes)-1], values[len(values)-1])
        self.avp_list.append(attribute_values)
        self.rules[self.current_index] = rule_set
        self.current_index += 1

        return self.current_index
    
    #Return the rules stored in the dictionary
    def get_policy(self) -> (dict):
        return self.rules

    #Goes through the attribute-value pairs and counts how frequently they appear
    def order_avp(self, avp: object) -> ():
        for i, attribute_value in enumerate(avp):
            found = False
            for curr_key in list(self.frequencies.keys()):
                if found:
                    break
                else:
                    if attribute_value.attribute + ":" + attribute_value.value == curr_key:
                        index = self.frequencies.get(curr_key)
                        self.frequencies[attribute_value.attribute + ":" + attribute_value.value] = index + 1
                        found = True
            if not found:
                self.frequencies[attribute_value.attribute + ":" + attribute_value.value] = 1

    #Sort dictionary based on the frequency of an attribute-value pair appearing
    def get_frequencies(self, avp: list) -> (list):
        curr_frequencies = {}

        for value in avp:
            curr_frequencies[value] = self.frequencies.get(value)

        sorted_frequencies = sorted(curr_frequencies, key=curr_frequencies.get, reverse=True)
        return sorted_frequencies

    #Look through the attribute-value pairs in the policy and look for the most common
    #If more than one policy find the most frequent attribute that is differnt between policies.
        #This provides a faster tree than always taking the first most common attribute-value pair.
    def find_best(self, avp_list: list, policy: object) -> (str):
        policy_attributes = self.find_entities(policy)
        curr_frequencies = self.get_frequencies(avp_list)
        highest = None

        for value in curr_frequencies:
            split = value.split(":")
            for val in avp_list:
                avp_split = val.split(":")
                if ((split[0] == avp_split[0]) and (split[1] != avp_split[1])):
                    highest = val
        if highest is None:
            highest = curr_frequencies[0]

        return highest

    #Look for rules that contain the most common attribute-value pair
    def find_rules(self, policy: object, highest_avp: str) -> (list, list):
        highest_avp_values = highest_avp.split(":")
        rules_found = []
        rules_nfound = []

        for i in range(len(policy)):
            found = False
            ruleset = policy[i]
            for i, rule in enumerate(ruleset):
                avp_1, avp_2 = rule
                if((avp_1.attribute == highest_avp_values[0] and avp_1.value == highest_avp_values[1]) or (highest_avp_values[0] == avp_2.attribute and avp_2.value == highest_avp_values[1])):
                    found = True
            if found:
                rules_found.append(ruleset)
            else:
                rules_nfound.append(ruleset)
        
        return rules_found, rules_nfound
    
    #Look for attribute-value pairs that appear in the policy
    def find_entities(self, policy: object) -> (set):
        attribute = set()
        for i in range(len(policy)):
            ruleset = policy[i]
            for i, rule in enumerate(ruleset):
                avp_1, avp_2 = rule
                attribute.add((avp_1.attribute + ":" + avp_1.value))
                attribute.add((avp_2.attribute + ":" + avp_2.value))

        return attribute

    #Extract the attributes-values that where found in the policy from the attribute list
    def find_attributes(self, avp_list: list, found_attributes: list) -> (list):
        attributes = []
        for i, value in enumerate(avp_list):
            for val in found_attributes:
                if val == value:
                    attributes.append(val)
        return attributes

#Based on the pseudocode in PolTree A Data Structure for Making Efficient Access decisions by Nath and Al.
class PolTree:
    def __init__(self, policy):
        self.tree = Tree()
        self.policy = policy
    
    #Recursive creation of the access control tree.
    def gen_bin_tree(self, policy: object, avp_ordered: list, direction = -1, root = None) -> ():
        #Base case when there are no policies that do not contain the attribute value pair
        if len(policy) == 0:
            return
        #We have reached the bottom of the tree, and now we will add the leaf nodes
        if len(policy) == 1:
            curr_str = ""
            if(len(avp_ordered) == 1):
                avp_values = avp_ordered[0].split(":")
                curr_str = avp_values[1]
                curr_root = self.tree.add(curr_str, False, root, direction=direction)
            #We have reached leaf nodes
            elif(len(avp_ordered) == 0):
                curr_root = root
            #If there are more than one attribute-value pairs left we will concatinate the attributes
            else:
                for i in range(len(avp_ordered) - 1):
                    avp_values = avp_ordered[i].split(":")
                    curr_str += avp_values[1] + ":"
                final_avp = avp_ordered[len(avp_ordered) - 1].split(":")
                curr_str += final_avp[1]
                curr_root = self.tree.add(curr_str, False, root, direction=direction)

            leaf_node_left = self.tree.add("Accept", True, curr_root, direction=1)
            leaf_node_right = self.tree.add("Deny", True, curr_root, direction=0)
        #Recursive step of expanding on the rules in the policy set that contain the selected attribute-value pair and those who don't
        else:
            avp = self.policy.find_best(avp_ordered, policy)
            avp_val = avp.split(":")
            curr_root = self.tree.add(avp_val[1], False, root, direction)
            p_includes, p_ninclude = self.policy.find_rules(policy, avp)
            avp_ordered.remove(avp)
            f_attributes = self.policy.find_attributes(avp_ordered, self.policy.find_entities(p_includes))
            nf_attributes = self.policy.find_attributes(avp_ordered, self.policy.find_entities(p_ninclude))

            self.gen_bin_tree(p_includes, f_attributes, direction=1, root=curr_root)
            self.gen_bin_tree(p_ninclude, nf_attributes, direction=0, root=curr_root)

    #Recursive function to process access request based on the attribute set provided by the requester
    @staticmethod
    def binary_resolver(tree: object, access_request: list, current_node: object) -> str:
        if current_node.leaf:
            return current_node.data
        else:
            avp = current_node.data
            matches = False
            avp_list = avp.split(":")
            count = 0
            for value in access_request:
                for avp_val in avp_list:
                    if value == avp_val or avp_val == "*":
                        if len(avp_list) > 1:
                            count += 1
                        else:
                            matches = True
                            break
            if count == len(avp_list):
                matches = True
            if matches:  
                if(current_node.left is None):
                    return "Accept"
                else:
                    #Match found for this attribute - transverse down the left branch
                    return PolTree.binary_resolver(tree, access_request, current_node.left)
            else:
                if(current_node.right is None):
                    return "Deny"
                else:
                    #Match not found for this attribute - transverse down the right branch
                    return PolTree.binary_resolver(tree, access_request, current_node.right)
    
    #wrapper for the recursive solver
    @staticmethod
    def process_access_request(tree, values):
        return PolTree.binary_resolver(tree, values, tree.root)

    def height(self, node):
        if node is None:
            return 0
    
        else :
    
            # Compute the depth of each subtree
            lDepth = self.height(node.left)
            rDepth = self.height(node.right)
    
            # Use the larger one
            if (lDepth > rDepth):
                return lDepth+1
            else:
                return rDepth+1
    
    def size(self, root):
        if root is None:
            return 0
        else:
            return 1 + self.size(root.left) + self.size(root.right)

    def byte_size(self, root):
        results = self.inorderTraversal(root)
        byte_size = 0
        for result in results:
            byte_size += result
        return byte_size

    #based on https://favtutor.com/blogs/tree-traversal-python-with-recursion
    def inorderTraversal(self, root):
        answer = []

        self.inorderTraversalUtil(root, answer)
        return answer

    def inorderTraversalUtil(self, root, answer):

        if root is None:
            return

        self.inorderTraversalUtil(root.left, answer)
        answer.append(sys.getsizeof(root))
        answer.append(sys.getsizeof(root.data))
        answer.append(sys.getsizeof(root.leaf))
        answer.append(sys.getsizeof(root.right))
        answer.append(sys.getsizeof(root.left))
        self.inorderTraversalUtil(root.right, answer)
        return

        

        

#Initializing - TODO make this easier for the user
#policy = Policy()
#first_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Professor", "CSE", "Assignment", "High", "Weekday", "Modify"])
#second_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Professor", "CSE", "Question Paper", "High", "Weekday", "Modify"])
#third_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Student", "CSE", "Assignment", "High", "Weekend", "Read"])
#fourth_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Professor", "ECE", "Assignment", "Low", "Weekend", "Modify"])
#fifth_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Professor", "ECE", "Question Paper", "Low", "Weekday", "Modify"])
#sixth_index = policy.create_rule(["Designation", "Department", "Type", "Confidentiality", "Day", "op"], ["AND", "AND", "AND", "AND", "AND", "AND"], ["Student", "ECE", "Assignment", "Low", "Weekend", "Read"])

#policy.order_avp(policy.avp_list)
#polTree = PolTree(policy)
#sorted_frequencies = sorted(policy.frequencies, key=policy.frequencies.get, reverse=True)
#polTree.gen_bin_tree(policy.rules, sorted_frequencies)
#print2D(polTree.tree.root)

#access_decision = PolTree.process_access_request(polTree.tree, ["Professor", "ECE", "Assignment", "Low", "Weekday", "Read"])
#print("acecss decision", access_decision)