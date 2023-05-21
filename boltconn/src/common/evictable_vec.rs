#[derive(Clone, Debug)]
pub struct EvictableVec<T> {
    in_mem_offset: usize,
    inner: Vec<T>,
}

impl<T> EvictableVec<T> {
    pub fn push(&mut self, val: T) {
        self.inner.push(val)
    }

    /// Get with logical offset
    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx < self.in_mem_offset {
            None
        } else {
            self.inner.get(idx - self.in_mem_offset)
        }
    }

    /// Logical length, including those evicted.
    pub fn logical_len(&self) -> usize {
        self.in_mem_offset + self.inner.len()
    }

    /// Real length with data in memory.
    pub fn real_len(&self) -> usize {
        self.inner.len()
    }

    pub fn current_offset(&self) -> usize {
        self.in_mem_offset
    }

    /// Evict elements with f. After the operation, only `left` at maximum remains in memory.
    pub fn evict_with<F: FnMut(&[T])>(&mut self, left: usize, f: F) {
        let vec_len = self.inner.len();
        if vec_len > left {
            let mid = vec_len - left;
            f(&self.inner[..mid]);
            self.in_mem_offset += mid;
            self.inner = self.inner.split_off(mid);
        }
    }
}
