#[derive(Copy, Clone, Debug)]
pub enum HeaderOpType {
    Add,
    Del,
    Replace,
    ReplaceWith,
}

#[derive(Copy, Clone, Debug)]
pub enum HeaderModType {
    Request(HeaderOpType),
    Response(HeaderOpType),
}
