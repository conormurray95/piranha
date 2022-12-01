use std::collections::{HashMap, HashSet};

use derive_builder::Builder;
use dsl::rule_toml::RuleToml;

#[derive(Clone, Builder, Default)]
pub struct PiranhaRule {
    /// Name of the rule. (It is unique)
    #[builder(setter(into))]
    name: String,
    /// Holes that need to be filled, in order to instantiate a rule
    #[builder(setter(into))]
    holes: HashSet<String>,
    /// Additional constraints for matching the rule
    // constraints: HashSet<Constraint>,
    /// The action that the rule will perform
    action: Action,

    grep_heuristics: HashSet<String>
}


#[derive(Debug, Clone)]
pub enum Action {
    /// This action will structurally match the code and rewrite it
    Rewrite{query: String, replace_node: String, replace: String},
    /// This action will only structurally match the code
    Match {query: String},
    /// Used for writing recursive rules
    Dummy
}

impl Default for Action {
    fn default() -> Self {
        Action::Dummy
    }
}


struct PiranhaRuleFactory;


impl PiranhaRuleFactory {

    fn new_rule(rule_toml: RuleToml){
        let b = PiranhaRuleBuilder::default()        
        .name(rule_toml.name())
        .holes(rule_toml.holes().unwrap_or_default())
        .build();
        if rule_toml.is_match_only_rule(){
            
        }
    }

}
