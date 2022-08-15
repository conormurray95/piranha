import toml
from toml import encoder
from os.path import join
import subprocess

def get_as_toml_literal(value):
    if "\n" in value:
        return f'""" {value}"""'
    return f'"{value}"'

def get_as_toml_literal_list(values):
    return "[" + ", ".join([get_as_toml_literal(v) for v in values]) + "]"

class Constraint :
    def __init__(self, matcher, queries):
        self.matcher = matcher
        self.queries = queries
    
    def as_toml(self):
        template = """[[rules.constraints]]
matcher = {matcher_str}
queries = {queries_str}
"""
        return template.format(matcher_str = get_as_toml_literal(self.matcher), 
            queries_str = get_as_toml_literal_list(self.queries))


class Rule :
    def __init__(self, name, query = None, replace_node = None, replace = None, groups = None, holes = None, constraints = []):
        self.name = name
        self.query = query
        self.replace_node = replace_node
        self.replace = replace 
        self.groups = groups
        self.holes = holes
        self.constraints = constraints
    
    def as_toml(self):
        toml_str = """[[rules]]
name = {}
""".format(get_as_toml_literal(self.name))

        if self.query:
            toml_str += "query= {}\n".format(get_as_toml_literal(self.query))
        if self.replace_node:
            toml_str += "replace_node= {}\n".format(get_as_toml_literal(self.replace_node))
            toml_str += "replace= {}\n".format(get_as_toml_literal(self.replace))
        if self.groups:
            toml_str += "groups= {}\n".format(get_as_toml_literal_list(self.groups))
        if self.holes:
            toml_str += "holes= {}\n".format(get_as_toml_literal_list(self.holes))
        if self.constraints:
            for c in self.constraints:
                toml_str += c.as_toml()
        return toml_str


class Edge :
    def __init__(self, source_rule , target_rules, scope):
        self.source_rule = source_rule
        self.target_rules = target_rules
        self.scope = scope
    
    def as_toml(self):
        template = """[[edges]]
scope = {}
from =  {}
to = {}

"""
        return template.format(get_as_toml_literal(self.scope), get_as_toml_literal(self.source_rule), get_as_toml_literal_list(self.target_rules))

class RuleGraph : 

    def __init__(self, languages):
        self.nodes = []
        self.edges = []
        self.languages = languages
        self.substitutions = {}

    def add_rule(self, rule):
        self.nodes.append(rule)

    def add_edge(self, edge):
        self.edges.append(edge)
    
    def add_substitutions(self, k, v):
        self.substitutions[k] = v
        
    def piranha_arguments_as_toml(self):
        template = """language = {}
substitutions = {}
"""
        subs_str = "[" + ", ".join([get_as_toml_literal_list([k, v]) for k, v in self.substitutions.items()]) + "]"
        return template.format(get_as_toml_literal_list(self.languages), subs_str)

    def as_tomls(self):
        rules = "\n".join([r.as_toml() for r in self.nodes])
        edges = "\n".join([e.as_toml() for e in self.edges])
        piranha_arguments = self.piranha_arguments_as_toml()
        return rules, edges, piranha_arguments
    
    def _write_to_file(self, content, path):
        with open(path, 'w+') as f:
            f.write(content)

    def apply(self, path_to_piranha_bin, path_to_target, path_to_configurations):
        rules = "\n".join([r.as_toml() for r in self.nodes])
        self._write_to_file(rules, join(path_to_configurations, 'rules.toml'))
        edges = "\n".join([e.as_toml() for e in self.edges])
        self._write_to_file(edges, join(path_to_configurations, 'edges.toml'))
        piranha_arguments = self.piranha_arguments_as_toml()
        self._write_to_file(piranha_arguments, join(path_to_configurations, 'piranha_arguments.toml'))
        args = ("./piranha", "-c", path_to_target, "-f", path_to_configurations )
        popen = subprocess.Popen(args, cwd= path_to_piranha_bin ,stdout=subprocess.PIPE)
        popen.wait()
        output = popen.stdout.read()
        print(output)



