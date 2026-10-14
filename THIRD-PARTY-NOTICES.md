# Third-party notices

claustrum is released under the MIT license (see [LICENSE](LICENSE)). It includes material
adapted from the following project.

## oh-my-pi

- Source: <https://github.com/can1357/oh-my-pi>
- License: MIT
- What is adapted: the API-key provider rows in `crates/credentials-core/src/catalog.rs` that
  carry a `// oh-my-pi auth/<key>.kdl` comment. Each row's display name, dashboard URL, key
  placeholder and validation probe were copied from the named file under
  `packages/catalog/src/compat/rules/auth/` (and, where a comment says so,
  `packages/catalog/src/compat/rules/providers/`) in that repository.

The license, as published in that repository:

```
MIT License

Copyright (c) 2025 Mario Zechner
Copyright (c) 2025-2026 Can Bölük
Copyright (c) 2026 Stencil Labs, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
