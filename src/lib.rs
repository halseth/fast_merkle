use std::error::Error;
use std::fmt;
use std::hash::Hasher;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Tree {
    leaves: Vec<Vec<u8>>,
    tree: Vec<[u8;32]>,
}

#[derive(Debug)]
pub struct SizeError {
    message: String,
}

impl fmt::Display for SizeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for SizeError{}

impl Tree {
   pub fn new(size: usize) -> Result<Self, SizeError> {
       if !usize::is_power_of_two(size) {
           return Err(SizeError{
               message: "not power of two".to_string(),
           })
       }
       Ok(Self {
           leaves: vec![vec![]; size],
           tree: vec![],
       })
   }

    pub fn root(&self) -> [u8; 32] {
        return [0; 32];
    }
}

#[cfg(test)]
mod tests {
    use std::panic::panic_any;
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn invalid_size() {
        let tree = Tree::new(5);
        match tree {
            Err(_)=> {},
            _ => panic!("expected size error"),
        }
    }

#[test]
fn new() {
    let tree = Tree::new(4).unwrap();
    assert_eq!(tree.leaves.len(), 4);

    let root = tree.root();
    let exp: [u8; 32] = [0; 32];
    assert_eq!(root, exp);
}
}
