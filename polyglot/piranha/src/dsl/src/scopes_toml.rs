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

use derive_builder::Builder;
use getset::Getters;
use serde_derive::Deserialize;

// Represents the content in the `scope_config.toml` file
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default, Builder, Getters)]
pub(crate) struct ScopeConfigToml {
  #[get = "pub"]
  scopes: Vec<ScopeGeneratorToml>,
}


#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default, Getters, Builder)]
pub(crate) struct ScopeQueryGeneratorToml {
  #[get = "pub"]
  matcher: String, // a tree-sitter query matching some enclosing AST pattern (like method or class)
  #[get = "pub"]
  generator: String, // a tree-sitter query matching the exact AST node
}


// Represents an entry in the `scope_config.toml` file
#[derive(Deserialize, Debug, Clone, Hash, PartialEq, Eq, Default, Builder, Getters)]
pub(crate) struct ScopeGeneratorToml {
  #[get = "pub"]
  name: String,
  #[get = "pub"]
  rules: Vec<ScopeQueryGeneratorToml>,
}

