use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use sha2::{Sha256, Digest};

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub struct Tree {
    size: usize,
    leaves: Vec<Vec<u8>>,
    tree: Vec<[u8; 32]>,
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

impl Error for SizeError {}

impl Tree {
    pub fn new(size: usize) -> Result<Self, SizeError> {
        if !usize::is_power_of_two(size) {
            return Err(SizeError {
                message: "not power of two".to_string(),
            });
        }
        let tree: Vec<[u8; 32]> = vec![[0; 32]; 2*size-1];
        let leaves = vec![vec![]; size];
        let mut s = Self {
            size,
            leaves,
            tree,
        };

        s.commit();
        Ok(s)
    }

    pub fn commit(&mut self) -> [u8; 32]{
        // Keep track of indexes to update.
        let mut updates: VecDeque<usize> = VecDeque::new();

        // Iterate leaves.
        for (i, leaf) in self.leaves.iter().enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(leaf);
            let hash = hasher.finalize();
            let hash_array: [u8; 32] = hash.into();
            let node= self.size-1+i;
            self.tree[node] = hash_array;

            println!("leaf {}={:x?} hash={:x?}", i, leaf, hash_array);

            // Push parent node to updates.
            if i%2 == 0 {
                updates.push_back((node-1)/2)
            }
        }

        // Iterate updates.
        let mut last_update: usize = 0;
        while !updates.is_empty() {
            let node = updates.pop_front().unwrap();

            // Skip double updates in case both children were updated.
            if node == last_update {
                continue;
            }

            let child0 = self.tree[2*node+1];
            let child1 = self.tree[2*node+2];

            let mut hasher = Sha256::new();
            hasher.update(child0);
            hasher.update(child1);
            let hash = hasher.finalize();
            let hash_array: [u8; 32] = hash.into();

            self.tree[node] = hash_array;
            last_update = node;

            // Push parent node to updates.
            if node != 0 {
                updates.push_back((node- 1) / 2)
            }
        }


        // Return new root.
        self.tree[0]
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::panic_any;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn invalid_size() {
        let tree = Tree::new(5);
        match tree {
            Err(_) => {}
            _ => panic!("expected size error"),
        }
    }

    #[test]
    fn new() {
        let size = 4;
        let tree = Tree::new(size).unwrap();
        assert_eq!(tree.leaves.len(), size);

        // Internal tree is double the size of leaves-1.
        assert_eq!(tree.tree.len(), 2*size-1);

        let zero_root_str = "5310a330e8f970388503c73349d80b45cd764db615f1bced2801dcd4524a2ff4";
        let zero_root: [u8; 32] = hex::decode(zero_root_str).unwrap().try_into().unwrap();

        let root = tree.root();
        assert_eq!(root, zero_root);
    }
}
