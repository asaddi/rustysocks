# rustysocks #

Yet another minimalistic SOCKS5 server, written in Rust. This one's asynchronous (with a little bit
of threading) using the [Tokio](https://crates.io/crates/tokio) runtime.

It supports only unauthenticated clients and only the CONNECT command. (And no real plans to go
beyond that. This is just a toy!)

## Inspiration ##

* [microsocks](https://github.com/rofl0r/microsocks)
* [socks5-rs](https://github.com/WANG-lp/socks5-rs)
* [merino](https://github.com/ajmwagar/merino)

I currently have need of a SOCKS5 server on my home network and I originally started with
microsocks. And then I wondered: what if it was asynchronous instead of threaded?

So after some digging around... I found that socks5-rs was asynchronous but
didn't support binding the outgoing connection to an interface/IP like I needed. And merino
was purely threaded with a non-functioning async port. (I tried to port it Tokio 1.0+ and
ultimately failed.) So I looked up RFC1928 and started from there.

And so the unoriginally-named rustysocks came to be, written over a weekend. It supports:

* Configurable listen IP (defaults to 0.0.0.0, or _all interfaces_)
* Configurable listen port (defaults to 1080, the standard SOCKS port)
* Configurable bind IP for outgoing connections (no binding by default)

All options are configurable via the command line. Type `rustysocks --help` for details.
