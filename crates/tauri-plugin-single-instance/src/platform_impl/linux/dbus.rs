use zbus::{connection::Builder, Connection};

pub(crate) type Callback = Box<dyn FnMut(Vec<String>, String) + Send + Sync + 'static>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ClaimError {
    #[error("single-instance ownership unavailable: {0}")]
    Unavailable(zbus::Error),
    #[error("single-instance handoff failed: {0}")]
    Delivery(zbus::Error),
}

pub(crate) enum Instance {
    Primary(PrimaryInstance),
    Secondary,
}

pub(crate) struct PrimaryInstance {
    connection: Connection,
    name: String,
}

impl PrimaryInstance {
    pub(crate) async fn release(&self) -> zbus::Result<()> {
        self.connection
            .release_name(self.name.as_str())
            .await
            .map(|_| ())
    }
}

struct Activation {
    callback: Callback,
}

#[zbus::interface(name = "org.SingleInstance.DBus")]
impl Activation {
    fn execute_callback(&mut self, argv: Vec<String>, cwd: String) {
        (self.callback)(argv, cwd);
    }
}

pub(crate) async fn claim_or_forward(
    builder: Builder<'_>,
    name: &str,
    path: &str,
    callback: Callback,
    arguments: Vec<String>,
    working_directory: String,
) -> Result<Instance, ClaimError> {
    // Install the interface before acquiring the name, so a racing secondary
    // cannot reach an owner whose activation endpoint is not ready yet.
    let connection = builder
        .serve_at(path, Activation { callback })
        .build()
        .await
        .map_err(ClaimError::Unavailable)?;
    match connection
        .request_name_with_flags(name, zbus::fdo::RequestNameFlags::DO_NOT_QUEUE)
        .await
    {
        Ok(_) => Ok(Instance::Primary(PrimaryInstance {
            connection,
            name: name.to_owned(),
        })),
        Err(zbus::Error::NameTaken) => {
            // Await the method reply before the secondary exits. Transport or
            // callback delivery failures must propagate rather than lose argv.
            connection
                .call_method(
                    Some(name),
                    path,
                    Some("org.SingleInstance.DBus"),
                    "ExecuteCallback",
                    &(arguments, working_directory),
                )
                .await
                .map_err(ClaimError::Delivery)?;
            Ok(Instance::Secondary)
        }
        Err(error) => Err(ClaimError::Unavailable(error)),
    }
}
