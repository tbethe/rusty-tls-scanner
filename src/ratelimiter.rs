use std::{
    thread::sleep,
    time::{Duration, Instant},
};

pub struct RateLimitedIter<I: Iterator> {
    prev: Option<Instant>,
    interval: Duration,
    iter: I,
}

pub trait RateLimit<I: Iterator> {
    /// Returns an iterator that has at least `interval` time inbetween
    /// two calls of `next()`. If `next()` is called faster, the function
    /// will block until `interval` time has elapsed.
    fn rate_limited(self, iterval: Duration) -> RateLimitedIter<I>;
}

impl<I> Iterator for RateLimitedIter<I>
where
    I: Iterator,
{
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self.prev {
            None => {
                self.prev = Some(Instant::now());
                self.iter.next()
            }
            Some(p) => {
                // default is 0
                let diff = self.interval.checked_sub(p.elapsed()).unwrap_or_default();
                if !diff.is_zero() {
                    sleep(diff);
                }
                self.prev = Some(Instant::now());
                self.iter.next()
            }
        }
    }
}

impl<I> RateLimit<I> for I
where
    I: Iterator,
{
    fn rate_limited(self, interval: Duration) -> RateLimitedIter<I> {
        RateLimitedIter {
            prev: None,
            interval,
            iter: self,
        }
    }
}
