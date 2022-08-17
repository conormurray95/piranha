pub mod config;
pub mod models;
pub mod piranha;
#[cfg(test)]
pub(crate) mod tests;
pub mod utilities;
use config::CommandLineArguments;
use itertools::Itertools;
use models::{piranha_output::PiranhaOutputSummary, rule::Rule, outgoing_edges::OutgoingEdges, rule_store::RuleStore};
use piranha::FlagCleaner;
use pyo3::prelude::*;

use crate::models::piranha_arguments::PiranhaArguments;

#[pyfunction]
pub fn execute_piranha_cli(
  path_to_codebase: String,
  path_to_configurations: String,
  path_to_output_summary: String
) -> Vec<PiranhaOutputSummary> {
  let args = PiranhaArguments::new(CommandLineArguments {
    path_to_codebase,
    path_to_configurations,
    path_to_output_summary: if path_to_output_summary.is_empty() { None } else {Option::Some(path_to_output_summary)},
  });

  let mut flag_cleaner = FlagCleaner::new(&args);
  flag_cleaner.perform_cleanup();
  flag_cleaner
      .get_updated_files()
      .iter()
      .map(|f| PiranhaOutputSummary::new(f))
      .collect_vec()
}

#[pyfunction]
pub fn execute_piranha_with_rules_edges(
  path_to_codebase: String,
  rules: Vec<Rule>,
  edges: Vec<OutgoingEdges>,
  language: String
) -> Vec<PiranhaOutputSummary> {


  let args = PiranhaArguments::new();




  // let args = PiranhaArguments::new(CommandLineArguments {
  //   path_to_codebase,
  //   path_to_configurations,
  //   path_to_output_summary: if path_to_output_summary.is_empty() { None } else {Option::Some(path_to_output_summary)},
  // });

  let mut flag_cleaner = FlagCleaner::new(&args);
  flag_cleaner.perform_cleanup();
  flag_cleaner
      .get_updated_files()
      .iter()
      .map(|f| PiranhaOutputSummary::new(f))
      .collect_vec()
}

#[pymodule]
#[pyo3(name = "piranha")]
fn execute_piranha_wrap(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
  m.add_function(wrap_pyfunction!(execute_piranha_cli, m)?)?;
  Ok(())
}
