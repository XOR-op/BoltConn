use crate::resource::buf_slab::PktBufPool;

#[derive(Clone)]
pub struct Shared {
    pub pool: PktBufPool,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            pool: PktBufPool::new(512),
        }
    }
}
