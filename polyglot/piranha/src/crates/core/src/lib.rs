use dsl::scopes::ScopeGenerator;
use source_code_unit::SourceCodeUnit;

pub mod piranha_config;
pub mod piranha_output;
pub mod rule_graph;
pub mod source_code_unit;
pub mod rule_store;
pub mod piranha_arguments;



impl ScopeGenerator {
    /// Generate a tree-sitter based query representing the scope of the previous edit.
    /// We generate these scope queries by matching the rules provided in `<lang>_scopes.toml`.
    pub(crate) fn get_scope_query(
      source_code_unit: SourceCodeUnit, scope_level: &str, start_byte: usize, end_byte: usize,
      rules_store: &mut RuleStore,
    ) -> String {
      let root_node = source_code_unit.root_node();
      let mut changed_node = get_node_for_range(root_node, start_byte, end_byte);
      // Get the scope matchers for `scope_level` from the `scope_config.toml`.
      let scope_matchers = rules_store.get_scope_query_generators(scope_level);
  
      // Match the `scope_matcher.matcher` to the parent
      loop {
        trace!(
          "Getting scope {} for node kind {}",
          scope_level,
          changed_node.kind()
        );
        for m in &scope_matchers {
          if let Some(p_match) = changed_node.get_match_for_query(
            &source_code_unit.code(),
            rules_store.query(&m.matcher()),
            false,
          ) {
            // Generate the scope query for the specific context by substituting the
            // the tags with code snippets appropriately in the `generator` query.
            return substitute_tags(m.generator().to_string(), p_match.matches(), true);
          }
        }
        if let Some(parent) = changed_node.parent() {
          changed_node = parent;
        } else {
          break;
        }
      }
      panic!("Could not create scope query for {:?}", scope_level);
    }
  }
