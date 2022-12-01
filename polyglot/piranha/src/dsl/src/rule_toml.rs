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

use std::collections::HashSet;
use serde_derive::Deserialize;

use super::{constraint_toml::ConstraintToml};

use getset::{ Getters, CopyGetters};

#[derive(Deserialize, Debug, Clone, Default)]
// Represents the `rules.toml` file
pub struct RulesToml {
  pub rules: Vec<RuleToml>,
}

#[derive(Deserialize, Debug, Clone, Default, Getters)]
pub struct RuleToml {
  /// Name of the rule. (It is unique)
  #[get = "pub"]
  name: String,
  /// Tree-sitter query as string
  #[get = "pub"]
  query: Option<String>,
  /// The tag corresponding to the node to be replaced
  // #[get = "pub"]
  replace_node: Option<String>,
  /// Replacement pattern
  #[get = "pub"]
  replace: Option<String>,
  /// Group(s) to which the rule belongs
  groups: Option<HashSet<String>>,
  /// Holes that need to be filled, in order to instantiate a rule
  #[get = "pub"]
  holes: Option<HashSet<String>>,
  /// Additional constraints for matching the rule
  constraints: Option<HashSet<ConstraintToml>>,
  /// Heuristics for identifying potential files containing occurrence of the rule.
  grep_heuristics: Option<HashSet<String>>,
}


impl RuleToml {
  // Dummy rules are helper rules that make it easier to define the rule graph.
  pub fn is_dummy_rule(&self) -> bool {
    self.query.is_none() && self.replace.is_none()
  }

  // Checks if a rule is `match-only` i.e. it has a query but no replace.
  pub fn is_match_only_rule(&self) -> bool {
    self.query.is_some() && self.replace.is_none()
  }
}
