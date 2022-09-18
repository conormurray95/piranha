/*
Copyright (c) 2022 Uber Technologies, Inc.

 <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 except in compliance with the License. You may obtain a copy of the License at
 <p>http://www.apache.org/licenses/LICENSE-2.0

 <p>Unless required by applicable law or agreed to in writing, software distributed under the
 License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 express or implied. See the License for the specific language governing permissions and
 limitations under the License.
*/

use itertools::Itertools;
use serde_derive::Deserialize;

use tree_sitter_wrapper::{
  get_node_for_range, substitute_tags, TreeSitterQueryHelpers,
};



// Represents the content in the `scope_config.toml` file
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct ScopeConfig {
  scopes: Vec<ScopeGenerator>,
}

impl ScopeConfig {
  /// Get a reference to the scope `config's` scopes.
  #[must_use]
  pub fn scopes(&self) -> Vec<ScopeGenerator> {
    self.scopes.iter().cloned().collect_vec()
  }
}

// Represents an entry in the `scope_config.toml` file
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct ScopeGenerator {
  name: String,
  rules: Vec<ScopeQueryGenerator>,
}

impl ScopeGenerator {
  pub fn name(&self) -> &str {
    self.name.as_ref()
  }

  pub fn rules(&self) -> Vec<ScopeQueryGenerator> {
    self.rules.iter().cloned().collect_vec()
  }
}

#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct ScopeQueryGenerator {
  matcher: String, // a tree-sitter query matching some enclosing AST pattern (like method or class)
  generator: String, // a tree-sitter query matching the exact AST node
}

impl ScopeQueryGenerator {
  pub fn matcher(&self) -> String {
    String::from(&self.matcher)
  }

  pub fn generator(&self) -> String {
    String::from(&self.generator)
  }
}

#[cfg(test)]
impl ScopeQueryGenerator {
  pub(crate) fn new(matcher: &str, generator: &str) -> ScopeQueryGenerator {
    ScopeQueryGenerator {
      matcher: matcher.to_string(),
      generator: generator.to_string(),
    }
  }
}
#[cfg(test)]
impl ScopeGenerator {
  pub(crate) fn new(name: &str, rules: Vec<ScopeQueryGenerator>) -> ScopeGenerator {
    ScopeGenerator {
      name: name.to_string(),
      rules,
    }
  }
}

// #[cfg(test)]
// #[path = "unit_tests/scopes_test.rs"]
// mod scopes_test;
