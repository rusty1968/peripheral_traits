use proposed_traits::digest::*;
use std::{convert::Infallible, marker::PhantomData};

struct Inner;


pub trait DigestInit: ErrorType {
    type InitParams;
    type OpContext<'a>: DigestOp where Self: 'a;

    fn init<'a>(&'a mut self, init_params: Self::InitParams) -> Result<Self::OpContext<'a>, Self::Error>;
}

struct Controller<'r> {
    _inner: &'r mut Inner,
}

impl ErrorType for Controller<'_> {
    type Error = Infallible; // Define your error type here
}

impl DigestInit for Controller<'_> {
    type InitParams = (); // Define your InitParams type here
    type OpContext<'a> = OpContextImpl<'a> where Self:'a; // Define your OpContext type here

    fn init<'a>(&'a mut self, _init_params: Self::InitParams) -> Result<Self::OpContext<'a>, Self::Error> {
        Ok(OpContextImpl {
            _marker: PhantomData,
        })
    }
}

struct OpContextImpl<'a> {
    _marker: PhantomData<&'a ()>,
}

impl<'a> proposed_traits::digest::ErrorType for OpContextImpl<'a> {
    type Error = Infallible;
}

impl<'a> DigestOp for OpContextImpl<'a> {

    fn update(&mut self, _input: &[u8]) -> Result<(), Self::Error> {
        // Implement the update logic here
        Ok(())
    }

    fn finalize(&mut self, _output: &mut [u8]) -> Result<(), Self::Error> {
        Ok(()) // Return the final output
    }
}
