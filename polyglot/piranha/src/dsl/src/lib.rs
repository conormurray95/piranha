use outgoing_edges_toml::EdgesToml;
use rule_toml::RulesToml;
use scopes_toml::{ScopeConfigToml, ScopeGeneratorToml};

pub mod rule_toml;
pub mod outgoing_edges_toml;
pub mod piranha_config_toml;
pub mod constraint_toml;
pub mod scopes_toml;


fn read_language_specific_rules(language_name: &str) -> RulesToml {
    match language_name {
      "java" => parse_toml(include_str!("../../cleanup_rules/java/rules.toml")),
      "kt" => parse_toml(include_str!("../../cleanup_rules/kt/rules.toml")),
      "swift" => parse_toml(include_str!("../../cleanup_rules/kt/rules.toml")),
      _ => RulesToml::default(),
    }
  }
  
  fn read_language_specific_edges(language_name: &str) -> EdgesToml {
    match language_name {
      "java" => parse_toml(include_str!("../../cleanup_rules/java/edges.toml")),
      "kt" => parse_toml(include_str!("../../cleanup_rules/kt/edges.toml")),
      _ => EdgesToml::default(),
    }
  }
  
  fn read_scope_config(language_name: &str) -> Vec<ScopeGeneratorToml> {
    match language_name {
      "java" => parse_toml::<ScopeConfigToml>(include_str!("../../cleanup_rules/java/scope_config.toml"))
        .scopes()
        .to_vec(),
      "kt" => parse_toml::<ScopeConfigToml>(include_str!("../../cleanup_rules/kt/scope_config.toml"))
        .scopes()
        .to_vec(),
      "swift" => parse_toml::<ScopeConfigToml>(include_str!("../../cleanup_rules/swift/scope_config.toml"))
        .scopes()
        .to_vec(),
      _ => Vec::new(),
    }
  }

pub(crate) fn parse_toml<T>(content: &str) -> T
where
  T: serde::de::DeserializeOwned + Default,
{
  return toml::from_str::<T>(content).unwrap();
}
