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

/// Captures the Piranha arguments by from the file at `path_to_feature_flag_rules`.
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default)]
pub(crate) struct PiranhaConfiguration {
  language: Vec<String>,
  substitutions: Vec<Vec<String>>,
  delete_file_if_empty: Option<bool>,
  delete_consecutive_new_lines: Option<bool>,
  global_tag_prefix: Option<String>,
  cleanup_comments_buffer: Option<usize>,
  cleanup_comments: Option<bool>,
}
