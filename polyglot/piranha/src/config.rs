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

//! This module contains all the `structs` and implementations required for - (i) handling Piranha's run-time arguments,
//! (ii) reading language specific configurations, and (iii) API specific configurations.
//! This module defines all basic building block `structs` used by Piranha.

use crate::{
  models::{
    outgoing_edges::{Edges},
    rule::{Rules},
    scopes::{ScopeConfig, ScopeGenerator},
  },
  utilities::read_toml,
};

use std::path::{PathBuf};

use clap::Parser;

/// A refactoring tool that eliminates dead code related to stale feature flags.
#[derive(Clone, Parser, Debug)]
#[clap(name = "Piranha")]
pub struct CommandLineArguments {
  /// Path to source code folder
  #[clap(short = 'c', long)]
  path_to_codebase: String,
  /// Directory containing the configuration files - `piranha_arguments.toml`, `rules.toml`,  and  `edges.toml` (optional)
  #[clap(short = 'f', long)]
  path_to_configurations: String,
  /// Path to output summary json
  #[clap(short = 'j', long)]
  path_to_output_summary: Option<String>,
}

impl CommandLineArguments {
    pub fn path_to_codebase(&self) -> &str {
        self.path_to_codebase.as_ref()
    }

    pub fn path_to_configurations(&self) -> &str {
        self.path_to_configurations.as_ref()
    }

    pub fn path_to_output_summary(&self) -> Option<String> {
        if let Some(s) = &self.path_to_output_summary{
          return Some(s.to_string());
        }
        None
    }
}




pub(crate) fn get_pre_built_rules(language_name: String) -> (Rules, Edges, Vec<ScopeGenerator>) {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path_to_language_specific_cleanup_config =
    &project_root.join(format!("src/cleanup_rules/{}", language_name));
    // Read the language specific cleanup rules and edges
    let language_rules: Rules = read_toml(
    &path_to_language_specific_cleanup_config.join("rules.toml"),
    true,
      );
    let language_edges: Edges = read_toml(
    &path_to_language_specific_cleanup_config.join("edges.toml"),
    true,
      );
    let scopes = read_toml::<ScopeConfig>(
    &path_to_language_specific_cleanup_config.join("scope_config.toml"),
    true,
      )
      .scopes();
    (language_rules, language_edges, scopes)
}
