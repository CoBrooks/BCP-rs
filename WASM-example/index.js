import { Bcp } from '../pkg/bcp_rs.js';

const bcp = new Bcp(128);
const { public: pk, private: sk } = bcp.gen_keypair(bcp);

const encrypted = bcp.encrypt(
  "Hello, World!",
  pk
);
console.log(encrypted);

const decrypted = bcp.decrypt(
  encrypted,
  sk
);
console.log(decrypted);

const decrypted_mk = bcp.decrypt_mk(
  encrypted,
  pk
);
console.log(decrypted_mk);
