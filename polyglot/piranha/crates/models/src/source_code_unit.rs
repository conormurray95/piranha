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
use std::{
  collections::{HashMap, VecDeque},
  fs,
  path::{Path, PathBuf},
};

use colored::Colorize;
use dsl::{constraint::Constraint, scopes::ScopeQueryGenerator};
use log::info;
use regex::Regex;
use tree_sitter::{InputEdit, Node, Parser, Range, Tree};
use tree_sitter_traversal::{traverse, Order};

use piranha_utilities::{
  eq_without_whitespace,
  // tree_sitter_wrapper::{get_replace_range, get_tree_sitter_edit, TreeSitterHelpers, get_context, substitute_tags},
};
use tree_sitter_wrapper::{get_replace_range, get_tree_sitter_edit,get_node_for_range, TreeSitterHelpers, get_context, substitute_tags, TreeSitterQueryHelpers, get_parser};
use tree_sitter_wrapper::matches::Match;
use crate::{ 
  edit::Edit, piranha_arguments::PiranhaArguments,
  rule_store::RuleStore
};
use dsl::{rule::Rule,};

use getset::{CopyGetters, Getters};
use dsl::scopes::ScopeGenerator;
// use crate::utilities::tree_sitter_wrapper::PiranhaHelpers;
use crate::{
  rule_store::{GLOBAL, PARENT},
  // utilities::tree_sitter_wrapper::get_node_for_range,
};

// Maintains the updated source code content and AST of the file
#[derive(Clone, Getters, CopyGetters)]
pub struct SourceCodeUnit {
  // The tree representing the file
  ast: Tree,
  // The content of a file
  #[getset(get = "pub")]
  code: String,
  // The tag substitution cache.
  // This map is looked up to instantiate new rules.
  #[getset(get = "pub")]
  substitutions: HashMap<String, String>,
  // The path to the source code.
  #[getset(get = "pub")]
  path: PathBuf,
  // Rewrites applied to this source code unit
  #[getset(get = "pub")]
  rewrites: Vec<Edit>,
  // Matches for the read_only rules in this source code unit
  #[getset(get = "pub")]
  matches: Vec<(String, Match)>,
  // Piranha Arguments passed by the user
  #[getset(get = "pub")]
  piranha_arguments: PiranhaArguments,
}

impl SourceCodeUnit {
  pub fn new(
    parser: &mut Parser, code: String, substitutions: &HashMap<String, String>, path: &Path,
    piranha_arguments: &PiranhaArguments,
  ) -> Self {
    let ast = parser.parse(&code, None).expect("Could not parse code");
    Self {
      ast,
      code,
      substitutions: substitutions.clone(),
      path: path.to_path_buf(),
      rewrites: Vec::new(),
      matches: Vec::new(),
      piranha_arguments: piranha_arguments.clone(),
    }
  }

  pub fn root_node(&self) -> Node<'_> {
    self.ast.root_node()
  }

  /// Writes the current contents of `code` to the file system.
  /// Based on the user's specifications, this function will delete a file if empty
  /// and replace three consecutive newline characters with two.
  pub fn persist(&self, piranha_arguments: &PiranhaArguments) {
    if self.code.as_str().is_empty() {
      if *piranha_arguments.delete_file_if_empty() {
        _ = fs::remove_file(&self.path).expect("Unable to Delete file");
      }
    } else {
      let content = if *piranha_arguments.delete_consecutive_new_lines() {
        let regex = Regex::new(r"\n(\s*\n)+(\s*\n)").unwrap();
        regex.replace_all(self.code(), "\n${2}").to_string()
      } else {
        self.code().to_string()
      };
      fs::write(&self.path, content).expect("Unable to Write file");
    }
  }

  pub(crate) fn apply_edit(&mut self, edit: &Edit, parser: &mut Parser) -> InputEdit {
    // Get the tree_sitter's input edit representation
    let mut applied_edit = self._apply_edit(
      edit.replacement_range(),
      edit.replacement_string(),
      parser,
      true,
    );
    // Check if the edit kind is "DELETE something"
    if *self.piranha_arguments.cleanup_comments() && edit.replacement_string().is_empty() {
      let deleted_at = edit.replacement_range().start_point.row;
      if let Some(comment_range) = self.get_comment_at_line(
        deleted_at,
        *self.piranha_arguments.cleanup_comments_buffer(),
        edit.replacement_range().start_byte,
      ) {
        info!("Deleting an associated comment");
        applied_edit = self._apply_edit(comment_range, "", parser, false);
      }
    }
    applied_edit
  }

  /// This function reports the range of the comment associated to the deleted element.
  ///
  /// # Arguments:
  /// * row : The row number where the deleted element started
  /// * buffer: Number of lines that we want to look up to find associated comment
  ///
  /// # Algorithm :
  /// Get all the nodes that either start and end at [row]
  /// If **all** nodes are comments
  /// * return the range of the comment
  /// If the [row] has no node that either starts/ends there:
  /// * recursively call this method for [row] -1 (until buffer is positive)
  fn get_comment_at_line(&mut self, row: usize, buffer: usize, start_byte: usize) -> Option<Range> {
    // Get all nodes that start or end on `updated_row`.
    let mut relevant_nodes_found = false;
    let mut relevant_nodes_are_comments = true;
    let mut comment_range = None;
    // Since the previous edit was a delete, the start and end of the replacement range is [start_byte].
    let node = self
      .ast
      .root_node()
      .descendant_for_byte_range(start_byte, start_byte)
      .unwrap_or(self.ast.root_node());

    for node in traverse(node.walk(), Order::Post) {
      if node.start_position().row == row || node.end_position().row == row {
        relevant_nodes_found = true;
        let is_comment: bool = self
          .piranha_arguments
          .language_name()
          .is_comment(node.kind());
        relevant_nodes_are_comments = relevant_nodes_are_comments && is_comment;
        if is_comment {
          comment_range = Some(node.range());
        }
      }
    }

    if relevant_nodes_found {
      if relevant_nodes_are_comments {
        return comment_range;
      }
    } else if buffer > 0 {
      // We pass [start_byte] itself, because we know that parent of the current row is the parent of the above row too.
      // If that's not the case, its okay, because we will not find any comments in these scenarios.
      return self.get_comment_at_line(row - 1, buffer - 1, start_byte);
    }
    None
  }

  /// Applies an edit to the source code unit
  /// # Arguments
  /// * `replace_range` - the range of code to be replaced
  /// * `replacement_str` - the replacement string
  /// * `parser`
  ///
  /// # Returns
  /// The `edit:InputEdit` performed.
  ///
  /// Note - Causes side effect. - Updates `self.ast` and `self.code`
  fn _apply_edit(
    &mut self, range: Range, replacement_string: &str, parser: &mut Parser, handle_error: bool,
  ) -> InputEdit {
    // Get the tree_sitter's input edit representation
    let (new_source_code, ts_edit) =
      get_tree_sitter_edit(self.code.clone(), range, replacement_string);
    // Apply edit to the tree
    self.ast.edit(&ts_edit);
    self._replace_file_contents_and_re_parse(&new_source_code, parser, true);
    // Handle errors, like removing extra comma.
    if self.ast.root_node().has_error() && handle_error {
      self.fix_syntax_for_comma_separated_expressions(parser);
    }
    ts_edit
  }

  // Replaces the content of the current file with the new content and re-parses the AST
  /// # Arguments
  /// * `replacement_content` - new content of file
  /// * `parser`
  /// * `is_current_ast_edited` : have you invoked `edit` on the current AST ?
  /// Note - Causes side effect. - Updates `self.ast` and `self.code`
  fn _replace_file_contents_and_re_parse(
    &mut self, replacement_content: &str, parser: &mut Parser, is_current_ast_edited: bool,
  ) {
    let prev_tree = if is_current_ast_edited {
      Some(&self.ast)
    } else {
      None
    };
    // Create a new updated tree from the previous tree
    let new_tree = parser
      .parse(&replacement_content, prev_tree)
      .expect("Could not generate new tree!");
    self.ast = new_tree;
    self.code = replacement_content.to_string();
  }

  // Tries to remove the extra comma -
  // -->  Remove comma if extra
  //    --> Check if AST has no errors, to decide if the replacement was successful.
  //      --->  if No: Undo the change
  //      --->  if Yes: Return
  // Returns true if the comma was successfully removed.
  fn try_to_remove_extra_comma(&mut self, parser: &mut Parser) -> bool {
    let c_ast = self.ast.clone();
    for n in traverse(c_ast.walk(), Order::Post) {
      // Remove the extra comma
      if n.is_extra() && eq_without_whitespace(n.utf8_text(self.code().as_bytes()).unwrap(), ",") {
        let current_version_code = self.code().clone();
        self._apply_edit(n.range(), "", parser, false);
        if self.ast.root_node().has_error() {
          // Undo the edit applied above
          self._replace_file_contents_and_re_parse(&current_version_code, parser, false);
        } else {
          return true;
        }
      }
    }
    false
  }

  // Tries to remove the extra comma -
  // Applies three Regex-Replacements strategies to the source file to remove the extra comma.
  // *  replace consecutive commas with comma
  // *  replace ( `(,` or `[,` ) with just `(` or `[`)
  // Check if AST has no errors, to decide if the replacement was successful.
  // Returns true if the comma was successfully removed.
  fn try_to_fix_code_with_regex_replace(&mut self, parser: &mut Parser) -> bool {
    let consecutive_comma_pattern = Regex::new(r",\s*\n*,").unwrap();
    let square_bracket_comma_pattern = Regex::new(r"\[\s*\n*,").unwrap();
    let round_bracket_comma_pattern = Regex::new(r"\(\s*\n*,").unwrap();
    let strategies = [
      (consecutive_comma_pattern, ","),
      (square_bracket_comma_pattern, "["),
      (round_bracket_comma_pattern, "("),
    ];

    let mut content = self.code().to_string();
    for (regex_pattern, replacement) in strategies {
      if regex_pattern.is_match(&content) {
        content = regex_pattern.replace_all(&content, replacement).to_string();
        self._replace_file_contents_and_re_parse(&content, parser, false);
      }
    }
    return !self.ast.root_node().has_error();
  }

  /// Sometimes our rewrite rules may produce errors (recoverable errors), like failing to remove an extra comma.
  /// This function, applies the recovery strategies.
  /// Currently, we only support recovering from extra comma.
  fn fix_syntax_for_comma_separated_expressions(&mut self, parser: &mut Parser) {
    let is_fixed =
      self.try_to_remove_extra_comma(parser) || self.try_to_fix_code_with_regex_replace(parser);

    if !is_fixed && traverse(self.ast.walk(), Order::Post).any(|n| n.is_error()) {
      panic!(
        "Produced syntactically incorrect source code {}",
        self.code()
      );
    }
  }
  // // #[cfg(test)] // Rust analyzer FP
  // pub(crate) fn code(&self) -> String {
  //   String::from(&self.code)
  // }

  // pub(crate) fn substitutions(&self) -> &HashMap<String, String> {
  //   &self.substitutions
  // }

  pub fn add_to_substitutions(
    &mut self, new_entries: &HashMap<String, String>, rule_store: &mut RuleStore,
  ) {
    let _ = &self.substitutions.extend(new_entries.clone());
    rule_store.add_global_tags(new_entries);
  }

  pub fn rewrites_mut(&mut self) -> &mut Vec<Edit> {
    &mut self.rewrites
  }

  pub fn matches_mut(&mut self) -> &mut Vec<(String, Match)> {
    &mut self.matches
  }

  /// Will apply the `rule` to all of its occurrences in the source code unit.
  fn apply_rule(
    &mut self, rule: Rule, rules_store: &mut RuleStore, parser: &mut Parser,
    scope_query: &Option<String>,
  ) {
    loop {
      if !self._apply_rule(rule.clone(), rules_store, parser, scope_query) {
        break;
      }
    }
  }

  /// Applies the rule to the first match in the source code
  /// This is implements the main algorithm of piranha.
  /// Parameters:
  /// * `rule` : the rule to be applied
  /// * `rule_store`: contains the input rule graph.
  ///
  /// Algorithm:
  /// * check if the rule is match only
  /// ** IF not (i.e. it is a rewrite):
  /// *** Get the first match of the rule for the file
  ///  (We only get the first match because the idea is that we will apply this change, and keep calling this method `_apply_rule` until all
  /// matches have been exhaustively updated.
  /// *** Apply the rewrite
  /// *** Update the substitution table
  /// *** Propagate the change
  /// ** Else (i.e. it is a match only rule):
  /// *** Get all the matches, and for each match
  /// *** Update the substitution table
  /// *** Propagate the change
  fn _apply_rule(
    &mut self, rule: Rule, rule_store: &mut RuleStore, parser: &mut Parser,
    scope_query: &Option<String>,
  ) -> bool {
    let scope_node = self.get_scope_node(scope_query, rule_store);

    let mut query_again = false;

    // When rule is a "rewrite" rule :
    // Update the first match of the rewrite rule
    // Add mappings to the substitution
    // Propagate each applied edit. The next rule will be applied relative to the application of this edit.
    if !rule.is_match_only_rule() {
      if let Some(edit) = self.get_edit(rule.clone(), rule_store, scope_node, true) {
        self.rewrites_mut().push(edit.clone());
        query_again = true;

        // Add all the (code_snippet, tag) mapping to the substitution table.
        self.add_to_substitutions(edit.matches(), rule_store);

        // Apply edit_1
        let applied_ts_edit = self.apply_edit(&edit, parser);

        self.propagate(get_replace_range(applied_ts_edit), rule, rule_store, parser);
      }
    }
    // When rule is a "match-only" rule :
    // Get all the matches
    // Add mappings to the substitution
    // Propagate each match. Note that,  we pass a identity edit (where old range == new range) in to the propagate logic.
    // The next edit will be applied relative to the identity edit.
    else {
      for m in self.get_matches(rule.clone(), rule_store, scope_node, true) {
        self.matches_mut().push((rule.name(), m.clone()));

        // In this scenario we pass the match and replace range as the range of the match `m`
        // This is equivalent to propagating an identity rule
        //  i.e. a rule that replaces the matched code with itself
        // Note that, here we DO NOT invoke the `_apply_edit` method and only update the `substitutions`
        // By NOT invoking this we simulate the application of an identity rule
        //
        self.add_to_substitutions(m.matches(), rule_store);

        self.propagate(m.range(), rule.clone(), rule_store, parser);
      }
    }
    query_again
  }

  /// This is the propagation logic of the Piranha's main algorithm.
  /// Parameters:
  ///  * `applied_ts_edit` -  it's(`rule`'s) application site (in terms of replacement range)
  ///  * `rule` - The `rule` that was just applied
  ///  * `rule_store` - contains the input "rule graph"
  ///  * `parser` - parser for the language
  /// Algorithm:
  ///
  /// (i) Lookup the `rule_store` and get all the (next) rules that could be after applying the current rule (`rule`).
  ///   * We will receive the rules grouped by scope:  `GLOBAL` and `PARENT` are applicable to each language. However, other scopes are determined
  ///     based on the `<language>/scope_config.toml`.
  /// (ii) Add the `GLOBAL` rule to the global rule list in the `rule_store` (This will be performed in the next iteration)
  /// (iii) Apply the local cleanup i.e. `PARENT` scoped rules
  ///  (iv) Go to step 1 (and repeat this for the applicable parent scoped rule. Do this until, no parent scoped rule is applicable.) (recursive)
  ///  (iv) Apply the rules based on custom language specific scopes (as defined in `<language>/scope_config.toml`) (recursive)
  ///
  fn propagate(
    &mut self, replace_range: Range, rule: Rule, rules_store: &mut RuleStore, parser: &mut Parser,
  ) {
    let mut current_replace_range = replace_range;

    let mut current_rule = rule.name();
    let mut next_rules_stack: VecDeque<(String, Rule)> = VecDeque::new();
    // Perform the parent edits, while queueing the Method and Class level edits.
    // let file_level_scope_names = [METHOD, CLASS];
    loop {
      // Get all the (next) rules that could be after applying the current rule (`rule`).
      let next_rules_by_scope = rules_store.get_next(&current_rule, self.substitutions());

      // Adds "Method" and "Class" rules to the stack
      self.add_rules_to_stack(
        &next_rules_by_scope,
        current_replace_range,
        rules_store,
        &mut next_rules_stack,
      );

      // Add Global rules as seed rules
      for r in &next_rules_by_scope[GLOBAL] {
        rules_store.add_to_global_rules(r, self.substitutions());
      }

      // Process the parent
      // Find the rules to be applied in the "Parent" scope that match any parent (context) of the changed node in the previous edit
      if let Some(edit) = self.get_edit_for_context(
        current_replace_range.start_byte,
        current_replace_range.end_byte,
        rules_store,
        &next_rules_by_scope[PARENT],
      ) {
        self.rewrites_mut().push(edit.clone());
        info!(
          "{}",
          format!(
            "Cleaning up the context, by applying the rule - {}",
            edit.matched_rule()
          )
          .green()
        );
        // Apply the matched rule to the parent
        let applied_edit = self.apply_edit(&edit, parser);
        current_replace_range = get_replace_range(applied_edit);
        current_rule = edit.matched_rule().to_string();
        // Add the (tag, code_snippet) mapping to substitution table.
        self.add_to_substitutions(edit.matches(), rules_store);
      } else {
        // No more parents found for cleanup
        break;
      }
    }

    // Apply the next rules from the stack
    for (sq, rle) in &next_rules_stack {
      self.apply_rule(rle.clone(), rules_store, parser, &Some(sq.to_string()));
    }
  }

  /// Adds the "Method" and "Class" scoped next rules to the queue.
  fn add_rules_to_stack(
    &mut self, next_rules_by_scope: &HashMap<String, Vec<Rule>>, current_match_range: Range,
    rules_store: &mut RuleStore, stack: &mut VecDeque<(String, Rule)>,
  ) {
    for (scope_level, rules) in next_rules_by_scope {
      // Scope level is not "PArent" or "Global"
      if ![PARENT, GLOBAL].contains(&scope_level.as_str()) {
        for rule in rules {
          let scope_query = self.get_scope_query(
            scope_level,
            current_match_range.start_byte,
            current_match_range.end_byte,
            rules_store,
          );
          // Add Method and Class scoped rules to the queue
          stack.push_front((scope_query, rule.instantiate(self.substitutions())));
        }
      }
    }
  }

  fn get_scope_node(&self, scope_query: &Option<String>, rules_store: &mut RuleStore) -> Node {
    // Get scope node
    // let mut scope_node = self.root_node();
    if let Some(query_str) = scope_query {
      // Apply the scope query in the source code and get the appropriate node
      let tree_sitter_scope_query = rules_store.query(query_str);
      if let Some(p_match) =
        &self
          .root_node()
          .get_match_for_query(self.code(), tree_sitter_scope_query, true)
      {
        return get_node_for_range(
          self.root_node(),
          p_match.range().start_byte,
          p_match.range().end_byte,
        );
      }
    }
    self.root_node()
  }

  /// Apply all `rules` sequentially.
  pub fn apply_rules(
    &mut self, rules_store: &mut RuleStore, rules: &[Rule], parser: &mut Parser,
    scope_query: Option<String>,
  ) {
    for rule in rules {
      self.apply_rule(rule.to_owned(), rules_store, parser, &scope_query)
    }
  }

  // Apply all the `rules` to the node, parent, grand parent and great grand parent.
  // Short-circuit on the first match.
  pub fn get_edit_for_context(&self,
    previous_edit_start: usize, previous_edit_end: usize,
    rules_store: &mut RuleStore, rules: &Vec<Rule>,
  ) -> Option<Edit> {
    let number_of_ancestors_in_parent_scope = *rules_store
      .get_number_of_ancestors_in_parent_scope();
    let changed_node = get_node_for_range(
      self.root_node(),
      previous_edit_start,
      previous_edit_end,
    );
    // Context contains -  the changed node in the previous edit, its's parent, grand parent and great grand parent
    let context = || {
      get_context(
        self.root_node(),
        changed_node,
        self.code().to_string(),
        number_of_ancestors_in_parent_scope,
      )
    };
    for rule in rules {
      for ancestor in &context() {
        if let Some(edit) = self.get_edit(rule.clone(), rules_store, *ancestor, false)
        {
          return Some(edit);
        }
      }
    }
    None
  }

  /// Gets the first match for the rule in `self`
  pub fn get_matches(
    &self, rule: Rule, rule_store: &mut RuleStore, node: Node,
    recursive: bool,
  ) -> Vec<Match> {
    let mut output: Vec<Match> = vec![];
    // Get all matches for the query in the given scope `node`.
    let replace_node_tag = if rule.is_match_only_rule() || rule.is_dummy_rule() {
      None
    } else {
      Some(rule.replace_node())
    };
    let all_query_matches = node.get_all_matches_for_query(
      self.code().to_string(),
      rule_store.query(&rule.query()),
      recursive,
      replace_node_tag,
    );

    // Return the first match that satisfies constraint of the rule
    for p_match in all_query_matches {
      let matched_node = get_node_for_range(
        self.root_node(),
        p_match.range().start_byte,
        p_match.range().end_byte,
      );

      if matched_node.is_satisfied(
        self,
        &rule,
        p_match.matches(),
        rule_store,
      ) {
        output.push(p_match);
      }
    }
    output
  }

  /// Gets the first match for the rule in `self`
  pub fn get_edit(
    &self, rule: Rule, rule_store: &mut RuleStore, node: Node,
    recursive: bool,
  ) -> Option<Edit> {
    // Get all matches for the query in the given scope `node`.

    return self
      .get_matches(rule.clone(), rule_store, node, recursive)
      .first()
      .map(|p_match| {
        let replacement = substitute_tags(rule.replace(), p_match.matches(), false);
        Edit::new(p_match.clone(), replacement, rule.name())
      });
  }


  /// Checks if the node satisfies the constraints.
  /// Constraint has two parts (i) `constraint.matcher` (ii) `constraint.query`.
  /// This function traverses the ancestors of the given `node` until `constraint.matcher` matches
  /// i.e. finds scope for constraint.
  /// Within this scope it checks if the `constraint.query` DOES NOT MATCH any sub-tree.
  pub fn is_satisfied(
    &self, node: Node, constraint: Constraint, rule_store: &mut RuleStore,
    substitutions: &HashMap<String, String>,
  ) -> bool {
    let mut current_node = node;
    // This ensures that the below while loop considers the current node too when checking for constraints.
    // It does not make sense to check for constraint if current node is a "leaf" node.
    if node.child_count() > 0 {
      current_node = node.child(0).unwrap();
    }
    // Get the scope_node of the constraint (`scope.matcher`)
    let mut matched_matcher = false;
    while let Some(parent) = current_node.parent() {
      let query_str = &constraint.matcher(substitutions);
      if let Some(p_match) =
        parent.get_match_for_query(self.code(), rule_store.query(query_str), false)
      {
        matched_matcher = true;
        let scope_node = get_node_for_range(
          self.root_node(),
          p_match.range().start_byte,
          p_match.range().end_byte,
        );
        for query_with_holes in constraint.queries() {
          let query_str = substitute_tags(query_with_holes.to_string(), substitutions, true);
          let query = &rule_store.query(&query_str);
          // If this query matches anywhere within the scope, return false.
          if scope_node
            .get_match_for_query(self.code(), query, true)
            .is_some()
          {
            return false;
          }
        }
        break;
      }
      current_node = parent;
    }
    matched_matcher
  }

  /// Generate a tree-sitter based query representing the scope of the previous edit.
  /// We generate these scope queries by matching the rules provided in `<lang>_scopes.toml`.
  pub fn get_scope_query(
    &self, scope_level: &str, start_byte: usize, end_byte: usize,
    rules_store: &mut RuleStore,
  ) -> String {
    let root_node = self.root_node();
    let mut changed_node = get_node_for_range(root_node, start_byte, end_byte);

    // Get the scope matchers for `scope_level` from the `scope_config.toml`.
    let scope_matchers = rules_store.get_scope_query_generators(scope_level);

    // Match the `scope_matcher.matcher` to the parent
    loop {
      for m in &scope_matchers {
        if let Some(p_match) = changed_node.get_match_for_query(
          self.code(),
          rules_store.query(&m.matcher()),
          false,
        ) {
          // Generate the scope query for the specific context by substituting the
          // the tags with code snippets appropriately in the `generator` query.
          return substitute_tags(m.generator(), p_match.matches(), true);
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


pub trait SatisfiesConstraint {
  // / Checks if the given rule satisfies the constraint of the rule, under the substitutions obtained upon matching `rule.query`
  fn is_satisfied(&self, source_code_unit: &SourceCodeUnit, rule: &Rule, substitutions: &HashMap<String, String>,rule_store: &mut RuleStore,) -> bool ;
}

impl SatisfiesConstraint for Node<'_> {
fn is_satisfied(
&self, source_code_unit: &SourceCodeUnit, rule: &Rule, substitutions: &HashMap<String, String>,
rule_store: &mut RuleStore,
) -> bool {
let updated_substitutions = &substitutions
  .clone()
  .into_iter()
  .chain(rule_store.default_substitutions())
  .collect();
rule.constraints().iter().all(|constraint| {
  source_code_unit.is_satisfied(
    *self,
    constraint.clone(),
    rule_store,
    updated_substitutions,
  )
})
}
}


/// Positive test for the generated scope query, given scope generators, source code and position of pervious edit.
#[test]
fn test_get_scope_query_positive() {
  let scope_generator_method = ScopeGenerator::new(
    "Method",
    vec![ScopeQueryGenerator::new(
      "((method_declaration 
          name : (_) @n
                parameters : (formal_parameters
                    (formal_parameter type:(_) @t0)
                        (formal_parameter type:(_) @t1)
                        (formal_parameter type:(_) @t2))) @xd2)",
      "(((method_declaration 
                        name : (_) @z
                              parameters : (formal_parameters
                                  (formal_parameter type:(_) @r0)
                                      (formal_parameter type:(_) @r1)
                                      (formal_parameter type:(_) @r2))) @qd)
                  (#eq? @z \"@n\")
                  (#eq? @r0 \"@t0\")
                  (#eq? @r1 \"@t1\")
                  (#eq? @r2 \"@t2\")
                  )",
    )],
  );

  let scope_generator_class = ScopeGenerator::new(
    "Class",
    vec![ScopeQueryGenerator::new(
      "(class_declaration name:(_) @n) @c",
      "(
          ((class_declaration name:(_) @z) @qc)
          (#eq? @z \"@n\")
          )",
    )],
  );

  let source_code = "class Test {
      pub void foobar(int a, int b, int c){
        boolean isFlagTreated = true;
        isFlagTreated = false;
        if (isFlagTreated) {
          System.out.println(a + b + c);
        }
      }
    }";

  let mut rule_store =
    RuleStore::dummy_with_scope(vec![scope_generator_method, scope_generator_class]);
  let mut parser = get_parser(String::from("java"));

  let source_code_unit = SourceCodeUnit::new(
    &mut parser,
    source_code.to_string(),
    &HashMap::new(),
    PathBuf::new().as_path(),
    rule_store.piranha_args()
  );

  let scope_query_method = source_code_unit.get_scope_query(
    "Method",
    133,
    134,
    &mut rule_store,
  );

  assert!(eq_without_whitespace(
    scope_query_method.as_str(),
    "(((method_declaration 
      name : (_) @z
            parameters : (formal_parameters
                (formal_parameter type:(_) @r0)
                    (formal_parameter type:(_) @r1)
                    (formal_parameter type:(_) @r2))) @qd)
            (#eq? @z \"foobar\")
            (#eq? @r0 \"int\")
            (#eq? @r1 \"int\")
            (#eq? @r2 \"int\")
            )"
  ));

  let scope_query_class =
  source_code_unit.get_scope_query( "Class", 133, 134, &mut rule_store);
  assert!(eq_without_whitespace(
    scope_query_class.as_str(),
    "(
        ((class_declaration name:(_) @z) @qc)
        (#eq? @z \"Test\")
        )"
  ));
}

/// Negative test for the generated scope query, given scope generators, source code and position of pervious edit.
#[test]
#[should_panic]
fn test_get_scope_query_negative() {
  let scope_generator_method = ScopeGenerator::new(
    "Method",
    vec![ScopeQueryGenerator::new(
      "((method_declaration 
          name : (_) @n
                parameters : (formal_parameters
                    (formal_parameter type:(_) @t0)
                        (formal_parameter type:(_) @t1)
                        (formal_parameter type:(_) @t2))) @xd2)",
      "(((method_declaration 
                        name : (_) @z
                              parameters : (formal_parameters
                                  (formal_parameter type:(_) @r0)
                                      (formal_parameter type:(_) @r1)
                                      (formal_parameter type:(_) @r2))) @qd)
                  (#eq? @z \"@n\")
                  (#eq? @r0 \"@t0\")
                  (#eq? @r1 \"@t1\")
                  (#eq? @r2 \"@t2\")
                  )",
    )],
  );

  let scope_generator_class = ScopeGenerator::new(
    "Class",
    vec![ScopeQueryGenerator::new(
      "(class_declaration name:(_) @n) @c",
      "(
          ((class_declaration name:(_) @z) @qc)
          (#eq? @z \"@n\")
          )",
    )],
  );

  let source_code = "class Test {
      pub void foobar(int a, int b, int c, int d){
        boolean isFlagTreated = true;
        isFlagTreated = false;
        if (isFlagTreated) {
          System.out.println(a + b + c + d);
        }
      }
    }";

  let mut rule_store =
    RuleStore::dummy_with_scope(vec![scope_generator_method, scope_generator_class]);
  let mut parser = get_parser(String::from("java"));

  let source_code_unit = SourceCodeUnit::new(
    &mut parser,
    source_code.to_string(),
    &HashMap::new(),
    PathBuf::new().as_path(),
    rule_store.piranha_args()
  );

  let _ = source_code_unit.get_scope_query( "Method", 133, 134, &mut rule_store);
}

 

// #[cfg(test)]
// #[path = "unit_tests/source_code_unit_test.rs"]
// mod source_code_unit_test;
