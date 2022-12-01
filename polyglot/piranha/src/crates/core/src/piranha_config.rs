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
use serde_derive::Deserialize;
use std::collections::HashMap;
use clap::Parser;
/// Captures the Piranha arguments by from the file at `path_to_feature_flag_rules`.
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct PiranhaConfiguration {
  language: Vec<String>,
  substitutions: Vec<Vec<String>>,
  delete_file_if_empty: Option<bool>,
  delete_consecutive_new_lines: Option<bool>,
  global_tag_prefix: Option<String>,
  cleanup_comments_buffer: Option<usize>,
  cleanup_comments: Option<bool>,
}

impl PiranhaConfiguration {
  pub fn substitutions(&self) -> HashMap<String, String> {
    self
      .substitutions
      .iter()
      .map(|x| (String::from(&x[0]), String::from(&x[1])))
      .collect()
  }

  pub fn language(&self) -> String {
    self.language[0].clone()
  }

  pub fn delete_file_if_empty(&self) -> Option<bool> {
    self.delete_file_if_empty
  }

  pub fn delete_consecutive_new_lines(&self) -> Option<bool> {
    self.delete_consecutive_new_lines
  }

  pub fn global_tag_prefix(&self) -> Option<String> {
    self.global_tag_prefix.clone()
  }

  pub fn cleanup_comments_buffer(&self) -> Option<usize> {
    self.cleanup_comments_buffer
  }

  pub fn cleanup_comments(&self) -> Option<bool> {
    self.cleanup_comments
  }
}


/// A refactoring tool that eliminates dead code related to stale feature flags.
#[derive(Clone, Parser, Debug)]
#[clap(name = "Piranha")]
pub struct CommandLineArguments {
  /// Path to source code folder
  #[clap(short = 'c', long)]
  pub path_to_codebase: String,
  /// Directory containing the configuration files - `piranha_arguments.toml`, `rules.toml`,  and  `edges.toml` (optional)
  #[clap(short = 'f', long)]
  pub path_to_configurations: String,
  /// Path to output summary json
  #[clap(short = 'j', long)]
  pub path_to_output_summary: Option<String>,
  /// Disables in-place rewriting of code
  #[clap(short = 'd', long, parse(try_from_str), default_value_t = false)]
  pub dry_run: bool,
}
