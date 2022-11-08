use hyper::{Body, Request, Response};

pub trait Modifier: Send + Sync {
    fn modify_request(&self, req: &mut Request<Body>);
    fn modify_response(&self, resp: &mut Response<Body>);
}

#[derive(Default)]
pub struct Logger;

impl Modifier for Logger {
    fn modify_request(&self, req: &mut Request<Body>) {
        println!("{:?}", req);
    }

    fn modify_response(&self, resp: &mut Response<Body>) {
        println!("{:?}", resp);
    }
}
