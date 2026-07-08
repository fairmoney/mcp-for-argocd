import { runTokenStoreContract } from './tokenStore.contract.js';
import { InMemoryTokenStore } from './inMemoryTokenStore.js';

runTokenStoreContract('memory', () => new InMemoryTokenStore());
