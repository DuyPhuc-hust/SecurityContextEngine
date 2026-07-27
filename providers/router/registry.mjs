export class ProviderRegistry {
  #providers = new Map();

  register(provider) {
    if (!provider?.id || !provider?.capabilities) throw new Error("Provider requires id and capabilities.");
    this.#providers.set(provider.id, provider);
  }

  list() { return [...this.#providers.values()]; }
}
