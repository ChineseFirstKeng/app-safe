/** SDK handshake failures may start close without awaiting it. Share that promise
 * so our finally waits for process termination before marking cleanup complete.
 * Each verifier owns a single-use transport; it is never restarted. */
export function awaitableTransportClose(transport: { close(): Promise<void> }): void {
  const close = transport.close.bind(transport);
  let pending: Promise<void> | undefined;
  transport.close = () => pending ??= close();
}
