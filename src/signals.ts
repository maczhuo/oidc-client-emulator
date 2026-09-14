// Share one pair of listeners across concurrent authorizations. Never remove host listeners.
const cancellations = new Set<() => void>();
const cancelAll = () => { for (const cancel of cancellations) cancel(); };

export function registerAuthorizationSignals(cancel: () => void): () => void {
  if (cancellations.size === 0) {
    process.on('SIGINT', cancelAll);
    process.on('SIGTERM', cancelAll);
  }
  cancellations.add(cancel);
  return () => {
    cancellations.delete(cancel);
    if (cancellations.size === 0) {
      process.off('SIGINT', cancelAll);
      process.off('SIGTERM', cancelAll);
    }
  };
}
