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

use crate::models::rule::SatisfiesConstraint;

use {
  super::Rule,
  crate::{
    models::{constraint::Constraint, rule_store::RuleStore, source_code_unit::SourceCodeUnit},
    utilities::tree_sitter_utilities::get_parser,
    models::piranha_arguments::{PiranhaArgumentsBuilder}
  },
  std::collections::HashMap,
  std::path::PathBuf,
};


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

#[test]
fn test_satisfies_constraints_positive() {
  let rule = Rule::new(
    "test",
    "(
      ((local_variable_declaration
                      declarator: (variable_declarator
                                          name: (_) @variable_name
                                          value: [(true) (false)] @init)) @variable_declaration)
      )",
    "variable_declaration",
    "",
    HashSet::new(),
    HashSet::from([Constraint::new(
      String::from("(method_declaration) @md"),
      vec![String::from(
        "(
         ((assignment_expression
                         left: (_) @a.lhs
                         right: (_) @a.rhs) @assignment)
         (#eq? @a.lhs \"@variable_name\")
         (#not-eq? @a.rhs \"@init\")
       )",
      )],
    )]),
  );
  let source_code = "class Test {
      pub void foobar(){
        boolean isFlagTreated = true;
        isFlagTreated = true;
        if (isFlagTreated) {
        // Do something;
        }
       }
      }";

  let mut rule_store = RuleStore::dummy();
  let language_name = String::from("java");
  let mut parser = get_parser(language_name.to_string());
  let piranha_args = PiranhaArgumentsBuilder::default().language_name(language_name).build().unwrap();
  let source_code_unit = SourceCodeUnit::new(
    &mut parser,
    source_code.to_string(),
    &HashMap::new(),
    PathBuf::new().as_path(),
    &piranha_args
  );

  let node = &source_code_unit
    .root_node()
    .descendant_for_byte_range(50, 72)
    .unwrap();

  assert!(node.is_satisfied(
    &source_code_unit,
    &rule,
    &HashMap::from([
      ("variable_name".to_string(), "isFlagTreated".to_string()),
      ("init".to_string(), "true".to_string())
    ]),
    &mut rule_store,
  ));
}
