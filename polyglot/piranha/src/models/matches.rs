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

use std::collections::HashMap;

use pyo3::prelude::*;
use tree_sitter::{Point, Range};

#[derive(serde_derive::Serialize, Debug, Clone)]
#[pyclass]
pub(crate) struct Match {
  // Range of the entire AST node captured by the match
  #[pyo3(get)]
  range: LocalRange,
  // The mapping between tags and string representation of the AST captured.
  #[pyo3(get)]
  matches: HashMap<String, String>,
}

impl Match {
  pub(crate) fn new(range: Range, matches: HashMap<String, String>) -> Self {
    Self {
      range: LocalRange::new(range),
      matches,
    }
  }

  /// Get the edit's replacement range.
  pub(crate) fn range(&self) -> Range {
    self.range.to_ts_range()
  }

  pub(crate) fn matches(&self) -> &HashMap<String, String> {
    &self.matches
  }
}

#[derive(serde_derive::Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[pyclass]
struct LocalRange {
  #[pyo3(get)]
  start_byte: usize,
  #[pyo3(get)]
  end_byte: usize,
  #[pyo3(get)]
  start_point: LocalPoint,
  #[pyo3(get)]
  end_point: LocalPoint,
}

impl LocalRange {
  fn new(range: Range) -> Self {
    Self {
      start_byte: range.start_byte,
      end_byte: range.end_byte,
      start_point: LocalPoint::new(range.start_point),
      end_point: LocalPoint::new(range.end_point),
    }
  }

  fn to_ts_range(&self) -> Range {
    Range {
      start_byte: self.start_byte,
      end_byte: self.end_byte,
      start_point: self.start_point.to_ts_point(),
      end_point: self.end_point.to_ts_point(),
    }
  }
}

/// A range of positions in a multi-line text document, both in terms of bytes and of
/// rows and columns.
#[derive(serde_derive::Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[pyclass]
struct LocalPoint {
  #[pyo3(get)]
  row: usize,
  #[pyo3(get)]
  column: usize,
}

impl LocalPoint {
  fn new(point: Point) -> Self {
    Self {
      row: point.row,
      column: point.column,
    }
  }

  fn to_ts_point(&self) -> Point {
    Point {
      row: self.row,
      column: self.column,
    }
  }
}
