//! Spawning a screen's requests so that they belong to the screen.
//!
//! A task spawned from an event handler belongs to the scope that
//! registered the handler. For a handler given to a component such as
//! `Button`, that is the component's own render; and a component with a
//! reactive prop (`loading: {|| busy.get()}`) renders again when the prop
//! changes, dropping that scope and every task it owns. Setting `busy` as a
//! request starts would so cancel the request it guards.
//!
//! [`Tasks`] records the owner of the component that creates it (during
//! its render) and spawns every task under that owner instead: a request
//! lives exactly as long as the screen that made it.

use std::future::Future;

use rinch::prelude::*;
use rinch::{Owner, current_owner};

/// Spawns futures owned by the component that created it.
#[derive(Clone, Copy)]
pub struct Tasks(Signal<Option<Owner>>);

impl Tasks {
    /// For the component now rendering. Call it in the component's body,
    /// not in a handler.
    pub fn here() -> Self {
        Self(Signal::new(current_owner()))
    }

    /// Run `future` on the UI thread, owned by this component: it is
    /// dropped if the component unmounts, and not before.
    pub fn spawn(self, future: impl Future<Output = ()> + 'static) {
        // The handlers that call this are the component's own, so its
        // signal is alive whenever one runs.
        match untracked(|| self.0.try_get()).flatten() {
            Some(owner) => {
                owner.run(|| spawn_local(future));
            }
            None => {
                spawn_local(future);
            }
        }
    }
}
