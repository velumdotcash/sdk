// Create browser-compatible shims
// path shim
const path = {
  join: (...args: string[]) => args.join('/'),
  resolve: (...args: string[]) => args.join('/'),
  dirname: (p: string) => p.split('/').slice(0, -1).join('/')
};

// fs shim - methods throw or return empty in browser
const fs = {
  readFileSync: (path: any) => {
    console.warn(`fs.readFileSync called in browser for ${path}`);
    return Buffer.from('');
  },
  existsSync: () => false,
  promises: {
    readFile: async () => Buffer.from('')
  }
};

// fileURLToPath shim
const fileURLToPath = (url: string) => url.replace('file://', '');

export { path, fs, fileURLToPath };
