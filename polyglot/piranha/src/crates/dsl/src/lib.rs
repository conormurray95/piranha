use outgoing_edges::Edges;
use rule::Rules;
use scopes::{ScopeGenerator, ScopeConfig};
use tree_sitter_wrapper::parse_toml;

pub mod rule;
pub mod constraint;
pub mod outgoing_edges;
pub mod scopes;


fn read_language_specific_rules(language_name: &str) -> Rules {
    match language_name {
      "java" => parse_toml(include_str!("cleanup_rules/java/rules.toml")),
      "kt" => parse_toml(include_str!("cleanup_rules/kt/rules.toml")),
      "swift" => parse_toml(include_str!("cleanup_rules/kt/rules.toml")),
      _ => Rules::default(),
    }
  }
  
  fn read_language_specific_edges(language_name: &str) -> Edges {
    match language_name {
      "java" => parse_toml(include_str!("cleanup_rules/java/edges.toml")),
      "kt" => parse_toml(include_str!("cleanup_rules/kt/edges.toml")),
      _ => Edges::default(),
    }
  }
  
  fn read_scope_config(language_name: &str) -> Vec<ScopeGenerator> {
    match language_name {
      "java" => parse_toml::<ScopeConfig>(include_str!("cleanup_rules/java/scope_config.toml"))
        .scopes()
        .to_vec(),
      "kt" => parse_toml::<ScopeConfig>(include_str!("cleanup_rules/kt/scope_config.toml"))
        .scopes()
        .to_vec(),
      "swift" => parse_toml::<ScopeConfig>(include_str!("cleanup_rules/swift/scope_config.toml"))
        .scopes()
        .to_vec(),
      _ => Vec::new(),
    }
  }
