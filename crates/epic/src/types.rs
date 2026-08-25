use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TypeDef {
    Struct(StructDef),
    Enum(EnumDef),
    Alias(AliasDef),
    Instruction(InstructionDef),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructDef {
    pub name: String,
    pub is_account: bool,
    pub fields: Vec<FieldDef>,
    pub attrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    pub type_ref: TypeRef,
    pub attrs: Vec<String>,
    /// Source line of this field declaration (1-indexed; 0 = unknown).
    #[serde(default)]
    pub line_number: usize,
    /// Source column of this field declaration (0-indexed; 0 = unknown).
    #[serde(default)]
    pub column_number: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TypeRef {
    Primitive(String),
    Array(Box<TypeRef>, usize),
    Vec(Box<TypeRef>),
    Option(Box<TypeRef>),
    Result(Box<TypeRef>, Box<TypeRef>),
    HashMap(Box<TypeRef>, Box<TypeRef>),
    BTreeMap(Box<TypeRef>, Box<TypeRef>),
    HashSet(Box<TypeRef>),
    BTreeSet(Box<TypeRef>),
    Tuple(Vec<TypeRef>),
    String,
    Pubkey,
    Custom(String),   // The raw string parsed
    Resolved(String), // The absolute path after resolution
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnumDef {
    pub name: String,
    pub variants: Vec<VariantDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VariantDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AliasDef {
    pub name: String,
    pub target: TypeRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionDef {
    pub name: String,
    pub args: Vec<FieldDef>,
}

use anyhow::{bail, Result};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TypeRegistry {
    // absolute_path -> TypeDef
    pub definitions: HashMap<String, TypeDef>,
    #[serde(default)]
    pub file_paths: HashMap<String, String>,
    #[serde(default)]
    pub module_paths: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub symbol_names: HashMap<String, String>,
}

impl TypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, absolute_path: String, def: TypeDef) {
        self.definitions.insert(absolute_path, def);
    }

    pub fn get(&self, absolute_path: &str) -> Option<&TypeDef> {
        self.definitions.get(absolute_path)
    }

    pub fn resolve_absolute_path(&self, current_module: &str, ident: &str) -> Result<String> {
        let direct_path = format!("{}::{}", current_module, ident);
        if self.definitions.contains_key(&direct_path) {
            return Ok(direct_path);
        }

        let mut matches = Vec::new();
        for key in self.definitions.keys() {
            if key.ends_with(&format!("::{}", ident)) || key == ident {
                matches.push(key.clone());
            }
        }
        // Sort for deterministic error messages and single-match selection.
        matches.sort();

        if matches.is_empty() {
            bail!("Unknown type: {}", ident);
        } else if matches.len() > 1 {
            if let Some(resolved) =
                self.resolve_ambiguous_by_imports(current_module, ident, &matches)
            {
                return Ok(resolved);
            }
            bail!("Ambiguous type: {} matches {:?}", ident, matches);
        } else {
            Ok(matches[0].clone())
        }
    }

    fn resolve_ambiguous_by_imports(
        &self,
        current_module: &str,
        ident: &str,
        candidates: &[String],
    ) -> Option<String> {
        let file_path = self.find_file_path_for_module(current_module)?;

        let mut best_candidate = None;
        let mut max_prefix_len = 0;
        let mut ambiguous_proximity = false;

        for candidate in candidates {
            if let Some(cand_file_path) = self.file_paths.get(candidate) {
                let prefix_len = common_prefix_len(&file_path, cand_file_path);
                if prefix_len > max_prefix_len {
                    max_prefix_len = prefix_len;
                    best_candidate = Some(candidate.clone());
                    ambiguous_proximity = false;
                } else if prefix_len == max_prefix_len && prefix_len > 0 {
                    ambiguous_proximity = true;
                }
            }
        }

        if let Some(resolved) = best_candidate {
            if !ambiguous_proximity {
                return Some(resolved);
            }
        }

        let source = std::fs::read_to_string(&file_path).ok()?;
        let imports = get_imports_from_source(&source);

        let current_module_segs: Vec<&str> = current_module.split("::").collect();
        let program_name = current_module_segs.first()?;

        for candidate in candidates {
            let candidate_segs: Vec<&str> = candidate.split("::").collect();

            for import in &imports {
                let mut resolved_import = Vec::new();
                let mut it = import.iter().peekable();
                if let Some(&first) = it.peek() {
                    if first == "crate" {
                        resolved_import.push(program_name.to_string());
                        it.next();
                    } else if first == "self" {
                        resolved_import.extend(current_module_segs.iter().map(|s| s.to_string()));
                        it.next();
                    } else if first == "super" {
                        if current_module_segs.len() > 1 {
                            resolved_import.extend(
                                current_module_segs[..current_module_segs.len() - 1]
                                    .iter()
                                    .map(|s| s.to_string()),
                            );
                        } else {
                            resolved_import.push(program_name.to_string());
                        }
                        it.next();
                    } else {
                        resolved_import.push(program_name.to_string());
                    }
                }
                for seg in it {
                    resolved_import.push(seg.clone());
                }

                if resolved_import.last().map(|s| s.as_str()) == Some("*") {
                    let prefix_len = resolved_import.len() - 1;
                    if candidate_segs.len() > prefix_len {
                        let candidate_prefix: Vec<String> = candidate_segs[..prefix_len]
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                        if candidate_prefix == resolved_import[..prefix_len]
                            && candidate_segs.last().copied() == Some(ident)
                        {
                            return Some(candidate.clone());
                        }
                    }
                } else {
                    let candidate_string_segs: Vec<String> =
                        candidate_segs.iter().map(|s| s.to_string()).collect();
                    if candidate_string_segs == resolved_import {
                        return Some(candidate.clone());
                    }
                }
            }
        }

        None
    }

    fn find_file_path_for_module(&self, current_module: &str) -> Option<String> {
        for (key, fp) in &self.file_paths {
            if key.starts_with(current_module) {
                return Some(fp.clone());
            }
        }
        None
    }
}

fn get_imports_from_source(source: &str) -> Vec<Vec<String>> {
    let mut imports = Vec::new();
    if let Ok(file) = syn::parse_str::<syn::File>(source) {
        for item in file.items {
            if let syn::Item::Use(item_use) = item {
                let mut prefix = Vec::new();
                collect_use_tree(&item_use.tree, &mut prefix, &mut imports);
            }
        }
    }
    imports
}

fn collect_use_tree(tree: &syn::UseTree, prefix: &mut Vec<String>, imports: &mut Vec<Vec<String>>) {
    match tree {
        syn::UseTree::Path(use_path) => {
            prefix.push(use_path.ident.to_string());
            collect_use_tree(&use_path.tree, prefix, imports);
            prefix.pop();
        }
        syn::UseTree::Name(use_name) => {
            let mut path = prefix.clone();
            path.push(use_name.ident.to_string());
            imports.push(path);
        }
        syn::UseTree::Rename(use_rename) => {
            let mut path = prefix.clone();
            path.push(use_rename.ident.to_string());
            imports.push(path);
        }
        syn::UseTree::Glob(_) => {
            let mut path = prefix.clone();
            path.push("*".to_string());
            imports.push(path);
        }
        syn::UseTree::Group(use_group) => {
            for item in &use_group.items {
                collect_use_tree(item, prefix, imports);
            }
        }
    }
}

fn common_prefix_len(path1: &str, path2: &str) -> usize {
    let chars1: Vec<char> = path1.chars().collect();
    let chars2: Vec<char> = path2.chars().collect();
    let mut len = 0;
    for (c1, c2) in chars1.iter().zip(chars2.iter()) {
        if c1 == c2 {
            len += 1;
        } else {
            break;
        }
    }
    len
}
