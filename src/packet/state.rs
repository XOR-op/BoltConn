use crate::packet::buf_pool::PktBufPool;

#[derive(Clone, Debug )]
pub struct Shared {
    pub pool: PktBufPool,
}
