use std::{collections::HashMap, path::PathBuf};

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

use crate::utilities::read_toml;

/// Captures the Piranha arguments by from the file at `path_to_feature_flag_rules`.
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct PiranhaConfiguration {
  pub(crate)language: Vec<String>,
  pub(crate) substitutions: Vec<Vec<String>>,
  pub(crate) delete_file_if_empty: Option<bool>,
  pub(crate) delete_consecutive_new_lines: Option<bool>,
  pub(crate) global_tag_prefix: Option<String>
}

impl PiranhaConfiguration {
  pub(crate) fn substitutions(&self) -> HashMap<String, String> {
    self
      .substitutions
      .iter()
      .map(|x| (String::from(&x[0]), String::from(&x[1])))
      .collect()
  }

  pub fn read_from(path_to_piranha_argument_file: &PathBuf) -> Self {
    read_toml(path_to_piranha_argument_file, false)
  }

  pub(crate) fn language(&self) -> String {
    self.language[0].clone()
  }

  pub(crate) fn delete_file_if_empty(&self) -> bool {
    if let Some(s) = self.delete_file_if_empty {
      return s;
    }
    return true;
  }

  pub(crate) fn delete_consecutive_new_lines(&self) -> bool {
    if let Some(s) = self.delete_consecutive_new_lines {
      return s;
    }
    return false;
  }

  pub(crate) fn global_tag_prefix(&self) -> &str {
    if let Some(t) = &self.global_tag_prefix {
      return t.as_str();
    }
    "GLOBAL_TAG."
  }

  pub fn set_substitutions(&mut self, substitutions: &HashMap<String, String>) {
    self.substitutions = substitutions
      .iter()
      .map(|(k, v)| vec![k.to_string(), v.to_string()])
      .collect_vec();
  }
}
