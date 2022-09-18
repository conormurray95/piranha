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


use {
  crate::{
    {rule::Rule, constraint::Constraint, },
    // utilities::tree_sitter_wrapper::get_parser,

  },
  std::collections::HashMap,
  std::path::PathBuf,
};
use tree_sitter_wrapper::get_parser;

/// Tests whether a valid rule can be correctly instantiated given valid substitutions.
#[test]
fn test_rule_try_instantiate_positive() {
  let holes = HashSet::from([String::from("variable_name")]);
  let rule = Rule::new("test","(((assignment_expression left: (_) @a.lhs right: (_) @a.rhs) @abc) (#eq? @a.lhs \"@variable_name\"))",
        "@abc", "",holes, HashSet::new());
  let substitutions: HashMap<String, String> = HashMap::from([
    (String::from("variable_name"), String::from("foobar")),
    (String::from("@a.lhs"), String::from("something")), // Should not substitute, since it `a.lhs` is not in `rule.holes`
  ]);
  let instantiated_rule = rule.try_instantiate(&substitutions);
  assert!(instantiated_rule.is_ok());
  assert_eq!(
    instantiated_rule.ok().unwrap().query(),
    "(((assignment_expression left: (_) @a.lhs right: (_) @a.rhs) @abc) (#eq? @a.lhs \"foobar\"))"
  )
}

/// Tests whether a valid rule can be is *not* instantiated given invalid substitutions.
#[test]
fn test_rule_try_instantiate_negative() {
  let rule = Rule::new("test","(((assignment_expression left: (_) @a.lhs right: (_) @a.rhs) @abc) (#eq? @a.lhs \"@variable_name\"))",
        "abc", "",HashSet::from([String::from("variable_name")]), HashSet::new());
  let substitutions: HashMap<String, String> = HashMap::from([
    (String::from("@a.lhs"), String::from("something")), // Should not substitute, since it `a.lhs` is not in `rule.holes`
  ]);
  let instantiated_rule = rule.try_instantiate(&substitutions);
  assert!(instantiated_rule.is_err());
}
