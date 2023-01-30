use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

// The transferred bytes from client to dest and from dest to client
pub struct TunnelStats {
    pub client_to_dest: usize,
    pub dest_to_client: usize,
}

pub struct Tunnel<C, T> {
    // Use option here since we will need to move (client, dest) out in Tunnel::start
    client_dest: Option<(C, T)>,
    client_name: String,
    dest_name: String,
}

impl<C, T> Tunnel<C, T>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub fn new(client_name: String, client: C, dest_name: String, dest: T) -> Self {
        Self {
            client_dest: Some((client, dest)),
            client_name,
            dest_name,
        }
    }

    pub async fn start(&mut self) -> io::Result<TunnelStats> {
        let (client, dest) = self.client_dest.take().unwrap();
        let (client_recv, client_send) = io::split(client);
        let (dest_recv, dest_send) = io::split(dest);

        let upstream_name = format!("{} -> {}", self.client_name, self.dest_name);
        let upstream_task =
            tokio::spawn(async move { Self::relay(&upstream_name, client_recv, dest_send).await });

        let downstream_name = format!("{} -> {}", self.dest_name, self.client_name);
        let downstream_task =
            tokio::spawn(
                async move { Self::relay(&downstream_name, dest_recv, client_send).await },
            );

        let downstream_stats = downstream_task.await??;
        let upstream_stats = upstream_task.await??;
        let stats = TunnelStats {
            client_to_dest: upstream_stats,
            dest_to_client: downstream_stats,
        };

        Ok(stats)
    }

    async fn relay<R: AsyncReadExt, W: AsyncWriteExt>(
        name: &str,
        mut source: ReadHalf<R>,
        mut destination: WriteHalf<W>,
    ) -> io::Result<usize> {
        const BUFFER_SIZE: usize = 16 * 1024;
        let mut buffer = [0; BUFFER_SIZE];
        let mut total = 0;
        loop {
            let len = source.read(&mut buffer).await?;
            if len == 0 {
                break;
            }
            destination.write_all(&buffer[..len]).await?;
            total += len;
            println!("{}: {} bytes", name, len);
        }
        destination.shutdown().await?;
        Ok(total)
    }
}