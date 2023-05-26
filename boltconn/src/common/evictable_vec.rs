#[derive(Clone, Debug)]
pub struct EvictableVec<T> {
    in_mem_offset: usize,
    inner: Vec<T>,
}

impl<T> EvictableVec<T> {
    pub fn new() -> Self {
        Self {
            in_mem_offset: 0,
            inner: Vec::new(),
        }
    }

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
    pub fn evict_with<F: FnMut(Vec<T>)>(&mut self, left: usize, mut f: F) {
        let vec_len = self.inner.len();
        if vec_len > left {
            let mid = vec_len - left;
            self.in_mem_offset += mid;
            let mut splitted = self.inner.split_off(mid);
            std::mem::swap(&mut splitted, &mut self.inner);
            f(splitted);
        }
    }

    /// Evict elements with evction from start to before the element pred(ele,left_len(including this ele)) returning false.
    /// Return the size of evicted elements.
    pub fn evict_until<F1: Fn(&T, usize) -> bool, F2: FnMut(Vec<T>)>(
        &mut self,
        pred: F1,
        mut eviction: F2,
    ) -> usize {
        let vec_len = self.inner.len();
        let mut idx = 0;
        for e in self.inner.iter() {
            if !pred(e, vec_len - idx) {
                break;
            }
            idx += 1;
        }
        let mut splitted = self.inner.split_off(idx);
        // keep the latter part
        std::mem::swap(&mut splitted, &mut self.inner);
        eviction(splitted);
        idx
    }

    pub fn logical_slice(&self, start: usize, end: Option<usize>) -> &[T] {
        match end {
            None => &self.inner.as_slice()[(start - self.in_mem_offset)..],
            Some(end) => {
                &self.inner.as_slice()[(start - self.in_mem_offset)..(end - self.in_mem_offset)]
            }
        }
    }
}

impl<T: Clone> EvictableVec<T> {
    pub fn as_vec(&self) -> Vec<T> {
        self.inner.clone()
    }

    pub fn get_last_n(&self, n: usize) -> Vec<T> {
        if self.inner.len() <= n {
            self.inner.clone()
        } else {
            let start = self.inner.len() - n;
            self.inner.as_slice()[start..].to_vec()
        }
    }
}
